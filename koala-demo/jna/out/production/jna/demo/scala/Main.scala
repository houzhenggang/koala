package demo.scala

import com.sun.jna.ptr.PointerByReference

/**
 * User: ya_feng_li@163.com
 * Date: 13-11-12
 * Time: 上午9:10
 */
object Main extends App {
  println("#######C Library########")
  val pstr=new PointerByReference()
  CLib.INSTANCE.j_say("ASDFASFSAF!@#@#!@#",pstr)
  println("@@"+pstr.getValue.getString(0))
  println(CLib.INSTANCE.j_add(12, 21))
  println("#######C++ Library########")
  CplusLib.INSTANCE.d_say("ASDFASFSAF!@#@#!@#")
  println(CplusLib.INSTANCE.d_add(34, 43))
}
