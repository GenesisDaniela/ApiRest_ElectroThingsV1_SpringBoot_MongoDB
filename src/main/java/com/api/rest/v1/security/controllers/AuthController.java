package com.api.rest.v1.security.controllers;

import java.text.ParseException;
import java.util.HashSet;
import java.util.Set;

import javax.mail.MessagingException;
import javax.validation.Valid;

import com.api.rest.v1.services.email.EmailServiceImp;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.api.rest.v1.security.dto.JwtDTO;
import com.api.rest.v1.security.dto.LoginUsuarioDTO;
import com.api.rest.v1.security.dto.SigninUsuarioDTO;
import com.api.rest.v1.security.entities.Usuario;
import com.api.rest.v1.security.enums.TipoRol;
import com.api.rest.v1.security.jwt.JwtProvider;
import com.api.rest.v1.security.services.UsuarioServiceImpl;

import io.swagger.annotations.ApiOperation;
import io.swagger.annotations.ApiResponse;
import io.swagger.annotations.ApiResponses;

@RestController
@RequestMapping("/api/v1/auth")
@CrossOrigin(origins = "*")
public class AuthController {

	@Autowired
	PasswordEncoder passwordEncoder;

	@Autowired
	AuthenticationManager authenticationManager;

	@Autowired
	UsuarioServiceImpl usuarioServiceImpl;

	@Autowired
	JwtProvider jwtProvider;

	@Autowired
	EmailServiceImp emailServiceImp;

	// ===============================================
	// ============= MÉTODOS HTTP ==============
	// ===============================================

	// =====================
	// ===== POST SIGNIN ===
	// =====================
	// ---INSERCIÓN DE USUARIOS---
	@ApiOperation(value = "Registro de Usuarios", notes = "Registro de Usuarios al Sistema")
	@ApiResponses(value = { @ApiResponse(code = 200, message = "Se ha Registrado el Usuario Correctamente"),
			@ApiResponse(code = 201, message = "Se ha Registrado el Usuario Correctamente"),
			@ApiResponse(code = 400, message = "No se pudo Registrar el Usuario. Comprobar la Solicitud"),
			@ApiResponse(code = 401, message = "No está autorizado para Registrar el Usuario. Verificar credenciales"),
			@ApiResponse(code = 403, message = "No se ha podido registrar el usuario correctamente. El servidor ha denegado esta operación"),
			@ApiResponse(code = 404, message = "La Inserción del Usuario no está Disponible ya que el recurso pedido no existe. Comprobar solicitud"),
			@ApiResponse(code = 405,  message = "El recurso ha sido deshabilitado."),
			@ApiResponse(code = 407,  message = "La autenticación debe estar hecha a partir de un proxy."),
			@ApiResponse(code = 408,  message = "Se ha superado el tiempo de espera entre la solicitud y el servidor. Intentar nuevamente"),
			@ApiResponse(code = 409,  message = "Se ha generado un conflicto en el servidor. Intentar nuevamente"),
			@ApiResponse(code = 410,  message = "El Contenido solicitado se ha Eliminado del Servidor."),
			@ApiResponse(code = 422,  message = "Se ha producido un error ya que los valores pasados no son correctos. Verificar campos"),
			@ApiResponse(code = 500,  message = "Se ha producido un error interno en el Servidor"),
			@ApiResponse(code = 503,  message = "Se ha producido un error de sobrecarga o mantenimiento en el Servidor. Intentar luego."),
			@ApiResponse(code = 505,  message = "Versión HTTP no es soportada por el Servidor."),
			@ApiResponse(code = 507,  message = "Almacenamiento Insuficiente por parte del Servidor.")
			})
	@PostMapping("/signin")
	public ResponseEntity<?> signin(@Valid @RequestBody SigninUsuarioDTO signinUsuario, BindingResult bindingResult) throws MessagingException {

		if (signinUsuario.getNombre().isBlank() 
				|| signinUsuario.getApellido().isBlank() 
				|| signinUsuario.getUsername().isBlank()
				|| signinUsuario.getPassword().isBlank()
				|| signinUsuario.getEmail().isBlank()) {
			return new ResponseEntity<String>("No se permiten campos vacios!!", HttpStatus.BAD_REQUEST);
		}

		if (usuarioServiceImpl.existsByUsername(signinUsuario.getUsername())) {
			return new ResponseEntity<String>("El Username ya existe en la DB!!", HttpStatus.BAD_REQUEST);
		}

		if (usuarioServiceImpl.existsByEmail(signinUsuario.getEmail())) {
			return new ResponseEntity<String>("El Email ya existe en la DB!!", HttpStatus.BAD_REQUEST);
		}

	
		if (bindingResult.hasErrors()) {
			return new ResponseEntity<String>("Campos o Email Inválidos!!", HttpStatus.BAD_REQUEST);
		}

		Usuario usuario = new Usuario(signinUsuario.getNombre(),signinUsuario.getApellido()
				, signinUsuario.getUsername(), passwordEncoder.encode(signinUsuario.getPassword())
				, signinUsuario.getEmail());

		Set<TipoRol> roles = new HashSet<>();

	
		if (signinUsuario.getRoles().contains("admin") || signinUsuario.getRoles().contains("ROLE_ADMIN")) {
			roles.add(TipoRol.ROLE_ADMIN);
			roles.add(TipoRol.ROLE_USER);
		}else {
			roles.add(TipoRol.ROLE_USER);
		}

		usuario.setRoles(roles);

		usuarioServiceImpl.addUsuario(usuario);

		//Envío de emails
		emailServiceImp.enviarEmail("Registro exitoso "+ usuario.getNombre(),

				"<!DOCTYPE html>\n" +
						"<html lang=\"en\">\n" +
						"\n" +
						"<head>\n" +
						"    <meta charset=\"UTF-8\">\n" +
						"    <meta http-equiv=\"X-UA-Compatible\" content=\"IE=edge\">\n" +
						"    <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">\n" +
						"    <title>Document</title>\n" +
						"</head>\n" +
						"\n" +
						"<body style=\"width: 800px\">\n" +
						"    <div style=\"background-color: rgb(218, 45, 45);; width: 100%; padding: 3rem 0;\">\n" +
						"        <div style=\"text-align: center; background-color: #ffffff; margin: 0 auto; width: 80%; border-radius: 8px;\">\n" +
						"            <img style=\"margin-top: 3rem; width: 190px\"\n" +
						"            <p style=\"margin: 1rem 0; font-size: 25px;\">Bienvenido</p>\n" +
						"            <p style=\"color: #424242;\">Hola, <b>"+usuario.getNombre() + " " +usuario.getApellido()+"</b>, te has registrado exitosamente en el aplicativo electroThings,"+
						" <br> ingresar al sistema:  \n" +
						"            </p>\n" +
						"            <div style=\"margin: 2rem auto; width: 120px; background-color: #4f46e5; padding: 8px; border-radius: 6px; \">\n" +
						"                <a style=\"color: #ffffff; text-decoration: none\" href=\""+ "https://app-electro-things-angular-boo-git-683385-santiagoandresserrano.vercel.app/"+"\">Continuar</a>\n" +
						"            </div>\n" +
						"            <div style=\"width: 100%; border-top: 2px solid rgb(218, 45, 45);; padding: 1rem 0\">\n" +
						"                <p>Copyright © 2022  <br> Todos los derechos reservados.</p>\n" +
						"            </div>\n" +
						"        </div>\n" +
						"    </div>\n" +
						"</body>\n" +
						"\n" +
						"</html>"

				,usuario.getEmail());

		return new ResponseEntity<SigninUsuarioDTO>(signinUsuario, HttpStatus.CREATED);
	}
	
	
	
	// =====================
		// ===== POST LOGIN ===
		// =====================
		// ---VALIDACIÓN DE USUARIOS---
	@ApiOperation(value = "Acceso de Usuarios", notes = "Acceso de Usuarios al Sistema")
	@ApiResponses(value = { @ApiResponse(code = 200, message = "Se ha Accedido al sistema Correctamente"),
			@ApiResponse(code = 201, message = "Se ha Accedido al sistema Correctamente"),
			@ApiResponse(code = 400, message = "No se pudo acceder al sistema. Comprobar la Solicitud"),
			@ApiResponse(code = 401, message = "No está autorizado para acceder al sistema. Verificar credenciales"),
			@ApiResponse(code = 403, message = "No se ha podido acceder al sistema correctamente. El servidor ha denegado esta operación"),
			@ApiResponse(code = 404, message = "El acceso al sistema no está Disponible ya que el recurso pedido no existe. Comprobar solicitud"),
			@ApiResponse(code = 405,  message = "El recurso ha sido deshabilitado."),
			@ApiResponse(code = 407,  message = "La autenticación debe estar hecha a partir de un proxy."),
			@ApiResponse(code = 408,  message = "Se ha superado el tiempo de espera entre la solicitud y el servidor. Intentar nuevamente"),
			@ApiResponse(code = 409,  message = "Se ha generado un conflicto en el servidor. Intentar nuevamente"),
			@ApiResponse(code = 410,  message = "El Contenido solicitado se ha Eliminado del Servidor."),
			@ApiResponse(code = 422,  message = "Se ha producido un error ya que los valores pasados no son correctos. Verificar campos"),
			@ApiResponse(code = 500,  message = "Se ha producido un error interno en el Servidor"),
			@ApiResponse(code = 503,  message = "Se ha producido un error de sobrecarga o mantenimiento en el Servidor. Intentar luego."),
			@ApiResponse(code = 505,  message = "Versión HTTP no es soportada por el Servidor."),
			@ApiResponse(code = 507,  message = "Almacenamiento Insuficiente por parte del Servidor.")
			})
	@PostMapping("/login")
	public ResponseEntity<?> login(@Valid @RequestBody LoginUsuarioDTO loginUsuario, BindingResult bindingResult) {

		if (bindingResult.hasErrors()) {
			return new ResponseEntity<String>("Campos Inválidos.!!", HttpStatus.BAD_REQUEST);
		}

		if (!(usuarioServiceImpl.existsByUsername(loginUsuario.getUsername()))) {
			return new ResponseEntity<String>("Usuario Inexistente. Verificar campos!!",
					HttpStatus.BAD_REQUEST);
		}

		Authentication authentication = authenticationManager.authenticate(
				new UsernamePasswordAuthenticationToken(loginUsuario.getUsername(), loginUsuario.getPassword()));

		SecurityContextHolder.getContext().setAuthentication(authentication);

		String jwt = jwtProvider.generateToken(authentication);

		JwtDTO jwtDto = new JwtDTO(jwt);

		return new ResponseEntity<JwtDTO>(jwtDto, HttpStatus.OK);
	}
	
	
	
	
	
	// ============================
	// ===== POST REFRESH TOKEN ===
	// ============================
	// ---VALIDACIÓN DE USUARIOS REFRESCADO---
	@ApiOperation(value = "Actualización de Token", notes = "Actualización de Token")
	@ApiResponses(value = { @ApiResponse(code = 200, message = "Se ha Actualizado el Token Correctamente"),
			@ApiResponse(code = 201, message = "Se ha Registrado el Actualizado el Token Correctamente"),
			@ApiResponse(code = 400, message = "No se pudo Registrar el Actualizado el Token. Comprobar la Solicitud"),
			@ApiResponse(code = 401, message = "No está autorizado para Registrar el Actualizado el Token. Verificar credenciales"),
			@ApiResponse(code = 403, message = "No se ha podido Actualizar el Token correctamente. El servidor ha denegado esta operación"),
			@ApiResponse(code = 404, message = "La Actualización del Token no está Disponible ya que el recurso pedido no existe. Comprobar solicitud"),
			@ApiResponse(code = 405,  message = "El recurso ha sido deshabilitado."),
			@ApiResponse(code = 407,  message = "La autenticación debe estar hecha a partir de un proxy."),
			@ApiResponse(code = 408,  message = "Se ha superado el tiempo de espera entre la solicitud y el servidor. Intentar nuevamente"),
			@ApiResponse(code = 409,  message = "Se ha generado un conflicto en el servidor. Intentar nuevamente"),
			@ApiResponse(code = 410,  message = "El Contenido solicitado se ha Eliminado del Servidor."),
			@ApiResponse(code = 422,  message = "Se ha producido un error ya que los valores pasados no son correctos. Verificar campos"),
			@ApiResponse(code = 500,  message = "Se ha producido un error interno en el Servidor"),
			@ApiResponse(code = 503,  message = "Se ha producido un error de sobrecarga o mantenimiento en el Servidor. Intentar luego."),
			@ApiResponse(code = 505,  message = "Versión HTTP no es soportada por el Servidor."),
			@ApiResponse(code = 507,  message = "Almacenamiento Insuficiente por parte del Servidor.")
			})
	@PostMapping("/refresh-token")
	public ResponseEntity<?> refreshToken(@RequestBody JwtDTO jwtDto) throws ParseException {

		String token = jwtProvider.refreshToken(jwtDto);

		JwtDTO jwtRefresh = new JwtDTO(token);

		return new ResponseEntity<JwtDTO>(jwtRefresh, HttpStatus.OK);

	}

}
