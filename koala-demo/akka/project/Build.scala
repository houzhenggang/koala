import sbt._
import Keys._
import io.Source
import net.virtualvoid.sbt.graph.Plugin._
import org.koala.sbt.SbtAppPlugin._

object Build extends Build {
  val reg="(.+)=(.+)".r
  val $ = Source.fromFile(new File(System.getProperty("user.dir"), "build.properties")).getLines()
          .filter(reg.findFirstMatchIn(_).isDefined).map(reg.findFirstMatchIn(_).get).map(m => (m.group(1) -> m.group(2))).toMap

  lazy val root = Project(
    id = "akka-demo",
    base = file("."),
    settings = Project.defaultSettings ++ Seq(
    name := "akka-demo",
    organization := "com.greatbit.dns",
    version := $("prod"),
    javacOptions ++= Seq("-encoding", "UTF-8"),
    scalacOptions ++= Seq("-encoding", "UTF-8"),
    libraryDependencies ++= Seq(
      "com.typesafe.akka" %% "akka-remote" % $("akka"),
      "com.typesafe.akka" %% "akka-kernel" % $("akka")
      //"com.typesafe.akka" %% "akka-slf4j" % $("akka")      
    ))) settings (appSettings: _*) settings (graphSettings: _*)  settings(prefix := "akka-demo", dirSetting ++= Seq("bin" -> "", "../shell/" -> ""))  
}