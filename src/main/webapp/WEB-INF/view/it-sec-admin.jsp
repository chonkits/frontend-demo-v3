<%@ page language="java" contentType="text/html; charset=ISO-8859-1"
	pageEncoding="ISO-8859-1"%>
<%@ taglib prefix="form" uri="http://www.springframework.org/tags/form"%>
<%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core"%>
<%@ taglib prefix="fn" uri="http://java.sun.com/jsp/jstl/functions"%>
<!DOCTYPE html>
<html>
<head>
<meta charset="ISO-8859-1">
<title>Integration between TYK and KeyCloak (POC)</title>
</head>
<body>
	<h1>Proof of Concept (POC) for integration between TYK and KeyCloak</h1>
	<h2>IT Security Administration</h2>
	<h3>Logged User: ${user.name}</h3>
	<hr>
	<h3>Access Token: ${page}</h3>
	<h3>Resource Access: ${resource_access}</h3>
	<hr>
	<c:if test="${not empty fn:trim(perm_tic)}">
		<h4>Permission Ticket: ${perm_tic}</h4>
		<hr>
		<h5>Authorized Permissions and Scopes: ${auth_perm}</h5>
		<hr>
		<h5>Permitted Roles: ${perm_res}</h5>
	</c:if>
	<c:if test="${empty fn:trim(perm_tic)}">
		<h4>Error: ${error}</h4>
	</c:if>
	<hr>
	<br>
	<form:form method="GET" id="form_back" action="${pageContext.request.contextPath}/">
		<input id="btn_back" type="submit" value="Back" />
	</form:form>
	<br>
	<form:form method="POST" id="form_logout" action="${pageContext.request.contextPath}/sso/logout">
		<input id="btn_logout" type="submit" value="Logout" />
	</form:form>
</body>
</html>