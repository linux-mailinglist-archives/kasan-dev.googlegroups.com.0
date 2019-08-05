Return-Path: <kasan-dev+bncBCTM5HN3U4ORBYNCUDVAKGQED7XUSOI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x339.google.com (mail-ot1-x339.google.com [IPv6:2607:f8b0:4864:20::339])
	by mail.lfdr.de (Postfix) with ESMTPS id 4098381811
	for <lists+kasan-dev@lfdr.de>; Mon,  5 Aug 2019 13:22:10 +0200 (CEST)
Received: by mail-ot1-x339.google.com with SMTP id d13sf45950911oth.20
        for <lists+kasan-dev@lfdr.de>; Mon, 05 Aug 2019 04:22:10 -0700 (PDT)
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:message-id:subject:mime-version
         :x-original-sender:precedence:mailing-list:list-id:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=co0YZZglJiq4Pez5YqtGQNZt1N/EXULdGaiyYTl6f2g=;
        b=cCkFa0qTi5N0KMRCZTIJ/uw5FTkSjiuE+iNAXMIJHcgmruLkldp/AtQAdlXoDbPiqK
         DsZn4Idl3krvP3fDTm1TLwQOp675w9eNFCLxzLCmITpXZx2vScvdHvXk1rYgiltSdodG
         R4Nbv8ZlYZUWsAC/VrfzGXb4wZ6bdH+xk1EHI7hhpi3cbooOjZfFv/8LikwKak60rYB7
         eBpGoj0nS9dasS2PwWmYB2Le7kEj+R3BFXZAjYQBYrDNqCbKebk3iPVf5/uLgbQ0aecJ
         i9DvUZgr7rI3DKC7Mu1SVUNOiERIHE8U57e7LaVf9xfH9jtYQNZGJtQaP3u+oQaTaJ/u
         +FgQ==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20161025;
        h=date:from:to:message-id:subject:mime-version:x-original-sender
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=co0YZZglJiq4Pez5YqtGQNZt1N/EXULdGaiyYTl6f2g=;
        b=djSG6h+zEq11DFnvPFxndRxv/mv86CQqn3tq3tEs21iO6LM0lTX7NfhpExOJcvJSmQ
         spK3fHBmXn8HaXKL3VizDOrswX6phTfuiAyVghp9784O61PYCJqRFkqVe9iU+xRxFPc2
         VRUoYgFnIMQeUX+dbCMxonMUl2OeAh387ATCQ8RvA4aKIC5qDYlwek8x8dpwnv+OBXJH
         +eU1ItAFKcxv6ui0+D4lSV7aMsPEa5l1YoAXebg6AarMqxEQxmuWjK1wMpH9952RxbiM
         ixZLtjRSwHY1LGGmBiv1oip1GYUpmDvZpEIupwmEfiMPEnmePNao9lu+b0sbPuP1t3pu
         kp/w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:message-id:subject
         :mime-version:x-original-sender:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=co0YZZglJiq4Pez5YqtGQNZt1N/EXULdGaiyYTl6f2g=;
        b=mFbvv80kcnM1KsL+n0zY/PqisVwiQ1w4hdRRZjnUCKv7mb4OICugNN+kz0AZK3Ht8z
         /VjI+OEluJuGLfTBJS2frAKWkacgz+loAHHR+OiQpWYNNWPUqpBxS0w5B/jD8K54uo3X
         3klDlWDf6Ljh7ZkQUTGS7F7/Y68RcT93/k+vHT5mKWowQYojfHXgMMM6BJbnBRwmsJJa
         hWIw+fvd1CRr160RzZjbCq8fFa9Er3PRhIdrW5ylnf/Ei2YrpIpA+7aeIWtKJB9Fgs4q
         +dESy+vmUIOv+HxpvqTe7Iii3OmOPhP7DmivvOpbGqExYjo1rvFdVMJbijTHeubzQBD6
         AWEA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAWbRA/+VLyJWl5M94pEAnEJR0wu0RQWTXwV/P6DcBEPvu2RAYzn
	g5DX8fYGTrs055pvXF7OO1g=
X-Google-Smtp-Source: APXvYqyVjbaS/bvYY7ZoK8VTwObXKiDwnYVmuRioKd0EwTEa6OPsAutl4yUQ4BT2lY6n09Rj8LGVEg==
X-Received: by 2002:a05:6830:1c5:: with SMTP id r5mr22946101ota.226.1565004129252;
        Mon, 05 Aug 2019 04:22:09 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aca:afd2:: with SMTP id y201ls199120oie.7.gmail; Mon, 05 Aug
 2019 04:22:09 -0700 (PDT)
X-Received: by 2002:aca:7507:: with SMTP id q7mr10671145oic.87.1565004128832;
        Mon, 05 Aug 2019 04:22:08 -0700 (PDT)
Date: Mon, 5 Aug 2019 04:22:08 -0700 (PDT)
From: manikantavstk@gmail.com
To: kasan-dev <kasan-dev@googlegroups.com>
Message-Id: <96b2546a-3540-4c08-9817-0468c3146fab@googlegroups.com>
Subject: I'm trying to build kasan for pixel 2 xl ( PQ3A.190705.001 ), But
 touch is not working.
MIME-Version: 1.0
Content-Type: multipart/mixed; 
	boundary="----=_Part_1517_1817126104.1565004128283"
X-Original-Sender: manikantavstk@gmail.com
Precedence: list
Mailing-list: list kasan-dev@googlegroups.com; contact kasan-dev+owners@googlegroups.com
List-ID: <kasan-dev.googlegroups.com>
X-Spam-Checked-In-Group: kasan-dev@googlegroups.com
X-Google-Group-Id: 358814495539
List-Post: <https://groups.google.com/group/kasan-dev/post>, <mailto:kasan-dev@googlegroups.com>
List-Help: <https://groups.google.com/support/>, <mailto:kasan-dev+help@googlegroups.com>
List-Archive: <https://groups.google.com/group/kasan-dev
List-Subscribe: <https://groups.google.com/group/kasan-dev/subscribe>, <mailto:kasan-dev+subscribe@googlegroups.com>
List-Unsubscribe: <mailto:googlegroups-manage+358814495539+unsubscribe@googlegroups.com>,
 <https://groups.google.com/group/kasan-dev/subscribe>

------=_Part_1517_1817126104.1565004128283
Content-Type: multipart/alternative; 
	boundary="----=_Part_1518_432675672.1565004128284"

------=_Part_1518_432675672.1565004128284
Content-Type: text/plain; charset="UTF-8"

Without kasan same build works fine. But after enabling kasan, compilation 
is successful but after flashing the images device touchscreen is not 
working.

Applied this patch:

+CONFIG_INPUT_TOUCHSCREEN=y
+CONFIG_LGE_TOUCH_CORE=y
+CONFIG_LGE_TOUCH_LGSIC_SW49408=m
+CONFIG_TOUCHSCREEN_FTM4=y
+CONFIG_TOUCHSCREEN_SYNAPTICS_DSX_HTC=y
+CONFIG_TOUCHSCREEN_SYNAPTICS_DSX_CORE_HTC=y
+CONFIG_TOUCHSCREEN_SYNAPTICS_DSX_RMI_DEV_HTC=y
+CONFIG_TOUCHSCREEN_SYNAPTICS_DSX_FW_UPDATE_HTC=y

Still no luck and touch isn't working. 
Can you provide any patch/ any inputs to resolve this touch problem?

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/96b2546a-3540-4c08-9817-0468c3146fab%40googlegroups.com.

------=_Part_1518_432675672.1565004128284
Content-Type: text/html; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

<div dir=3D"ltr">Without kasan same build works fine. But after enabling ka=
san, compilation is successful but after flashing the images device touchsc=
reen is not working.<div><br></div><div>Applied this patch:</div><div><br><=
/div><div><span style=3D"color: rgb(51, 51, 51); font-family: -apple-system=
, BlinkMacSystemFont, &quot;Segoe UI&quot;, Roboto, Oxygen, Ubuntu, &quot;F=
ira Sans&quot;, &quot;Droid Sans&quot;, &quot;Helvetica Neue&quot;, sans-se=
rif; font-size: 14px; background-color: rgb(243, 249, 244);">+CONFIG_INPUT_=
TOUCHSCREEN=3Dy</span><br style=3D"color: rgb(51, 51, 51); font-family: -ap=
ple-system, BlinkMacSystemFont, &quot;Segoe UI&quot;, Roboto, Oxygen, Ubunt=
u, &quot;Fira Sans&quot;, &quot;Droid Sans&quot;, &quot;Helvetica Neue&quot=
;, sans-serif; font-size: 14px; background-color: rgb(243, 249, 244);"><spa=
n style=3D"color: rgb(51, 51, 51); font-family: -apple-system, BlinkMacSyst=
emFont, &quot;Segoe UI&quot;, Roboto, Oxygen, Ubuntu, &quot;Fira Sans&quot;=
, &quot;Droid Sans&quot;, &quot;Helvetica Neue&quot;, sans-serif; font-size=
: 14px; background-color: rgb(243, 249, 244);">+CONFIG_LGE_TOUCH_CORE=3Dy</=
span><br style=3D"color: rgb(51, 51, 51); font-family: -apple-system, Blink=
MacSystemFont, &quot;Segoe UI&quot;, Roboto, Oxygen, Ubuntu, &quot;Fira San=
s&quot;, &quot;Droid Sans&quot;, &quot;Helvetica Neue&quot;, sans-serif; fo=
nt-size: 14px; background-color: rgb(243, 249, 244);"><span style=3D"color:=
 rgb(51, 51, 51); font-family: -apple-system, BlinkMacSystemFont, &quot;Seg=
oe UI&quot;, Roboto, Oxygen, Ubuntu, &quot;Fira Sans&quot;, &quot;Droid San=
s&quot;, &quot;Helvetica Neue&quot;, sans-serif; font-size: 14px; backgroun=
d-color: rgb(243, 249, 244);">+CONFIG_LGE_TOUCH_LGSIC_SW49408=3Dm</span><br=
 style=3D"color: rgb(51, 51, 51); font-family: -apple-system, BlinkMacSyste=
mFont, &quot;Segoe UI&quot;, Roboto, Oxygen, Ubuntu, &quot;Fira Sans&quot;,=
 &quot;Droid Sans&quot;, &quot;Helvetica Neue&quot;, sans-serif; font-size:=
 14px; background-color: rgb(243, 249, 244);"><span style=3D"color: rgb(51,=
 51, 51); font-family: -apple-system, BlinkMacSystemFont, &quot;Segoe UI&qu=
ot;, Roboto, Oxygen, Ubuntu, &quot;Fira Sans&quot;, &quot;Droid Sans&quot;,=
 &quot;Helvetica Neue&quot;, sans-serif; font-size: 14px; background-color:=
 rgb(243, 249, 244);">+CONFIG_TOUCHSCREEN_FTM4=3Dy</span><br style=3D"color=
: rgb(51, 51, 51); font-family: -apple-system, BlinkMacSystemFont, &quot;Se=
goe UI&quot;, Roboto, Oxygen, Ubuntu, &quot;Fira Sans&quot;, &quot;Droid Sa=
ns&quot;, &quot;Helvetica Neue&quot;, sans-serif; font-size: 14px; backgrou=
nd-color: rgb(243, 249, 244);"><span style=3D"color: rgb(51, 51, 51); font-=
family: -apple-system, BlinkMacSystemFont, &quot;Segoe UI&quot;, Roboto, Ox=
ygen, Ubuntu, &quot;Fira Sans&quot;, &quot;Droid Sans&quot;, &quot;Helvetic=
a Neue&quot;, sans-serif; font-size: 14px; background-color: rgb(243, 249, =
244);">+CONFIG_TOUCHSCREEN_SYNAPTICS_DSX_HTC=3Dy</span><br style=3D"color: =
rgb(51, 51, 51); font-family: -apple-system, BlinkMacSystemFont, &quot;Sego=
e UI&quot;, Roboto, Oxygen, Ubuntu, &quot;Fira Sans&quot;, &quot;Droid Sans=
&quot;, &quot;Helvetica Neue&quot;, sans-serif; font-size: 14px; background=
-color: rgb(243, 249, 244);"><span style=3D"color: rgb(51, 51, 51); font-fa=
mily: -apple-system, BlinkMacSystemFont, &quot;Segoe UI&quot;, Roboto, Oxyg=
en, Ubuntu, &quot;Fira Sans&quot;, &quot;Droid Sans&quot;, &quot;Helvetica =
Neue&quot;, sans-serif; font-size: 14px; background-color: rgb(243, 249, 24=
4);">+CONFIG_TOUCHSCREEN_SYNAPTICS_DSX_CORE_HTC=3Dy</span><br style=3D"colo=
r: rgb(51, 51, 51); font-family: -apple-system, BlinkMacSystemFont, &quot;S=
egoe UI&quot;, Roboto, Oxygen, Ubuntu, &quot;Fira Sans&quot;, &quot;Droid S=
ans&quot;, &quot;Helvetica Neue&quot;, sans-serif; font-size: 14px; backgro=
und-color: rgb(243, 249, 244);"><span style=3D"color: rgb(51, 51, 51); font=
-family: -apple-system, BlinkMacSystemFont, &quot;Segoe UI&quot;, Roboto, O=
xygen, Ubuntu, &quot;Fira Sans&quot;, &quot;Droid Sans&quot;, &quot;Helveti=
ca Neue&quot;, sans-serif; font-size: 14px; background-color: rgb(243, 249,=
 244);">+CONFIG_TOUCHSCREEN_SYNAPTICS_DSX_RMI_DEV_HTC=3Dy</span><br style=
=3D"color: rgb(51, 51, 51); font-family: -apple-system, BlinkMacSystemFont,=
 &quot;Segoe UI&quot;, Roboto, Oxygen, Ubuntu, &quot;Fira Sans&quot;, &quot=
;Droid Sans&quot;, &quot;Helvetica Neue&quot;, sans-serif; font-size: 14px;=
 background-color: rgb(243, 249, 244);"><span style=3D"color: rgb(51, 51, 5=
1); font-family: -apple-system, BlinkMacSystemFont, &quot;Segoe UI&quot;, R=
oboto, Oxygen, Ubuntu, &quot;Fira Sans&quot;, &quot;Droid Sans&quot;, &quot=
;Helvetica Neue&quot;, sans-serif; font-size: 14px; background-color: rgb(2=
43, 249, 244);">+CONFIG_TOUCHSCREEN_SYNAPTICS_DSX_FW_UPDATE_HTC=3Dy</span><=
br></div><div><span style=3D"color: rgb(51, 51, 51); font-family: -apple-sy=
stem, BlinkMacSystemFont, &quot;Segoe UI&quot;, Roboto, Oxygen, Ubuntu, &qu=
ot;Fira Sans&quot;, &quot;Droid Sans&quot;, &quot;Helvetica Neue&quot;, san=
s-serif; font-size: 14px; background-color: rgb(243, 249, 244);"><br></span=
></div><div><span style=3D"color: rgb(51, 51, 51); font-family: -apple-syst=
em, BlinkMacSystemFont, &quot;Segoe UI&quot;, Roboto, Oxygen, Ubuntu, &quot=
;Fira Sans&quot;, &quot;Droid Sans&quot;, &quot;Helvetica Neue&quot;, sans-=
serif; font-size: 14px; background-color: rgb(243, 249, 244);">Still no luc=
k and touch isn&#39;t working.=C2=A0</span></div><div><span style=3D"color:=
 rgb(51, 51, 51); font-family: -apple-system, BlinkMacSystemFont, &quot;Seg=
oe UI&quot;, Roboto, Oxygen, Ubuntu, &quot;Fira Sans&quot;, &quot;Droid San=
s&quot;, &quot;Helvetica Neue&quot;, sans-serif; font-size: 14px; backgroun=
d-color: rgb(243, 249, 244);">Can you provide any patch/ any inputs to reso=
lve this touch problem?</span></div></div>

<p></p>

-- <br />
You received this message because you are subscribed to the Google Groups &=
quot;kasan-dev&quot; group.<br />
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to <a href=3D"mailto:kasan-dev+unsubscribe@googlegroups.com">kasan-dev=
+unsubscribe@googlegroups.com</a>.<br />
To view this discussion on the web visit <a href=3D"https://groups.google.c=
om/d/msgid/kasan-dev/96b2546a-3540-4c08-9817-0468c3146fab%40googlegroups.co=
m?utm_medium=3Demail&utm_source=3Dfooter">https://groups.google.com/d/msgid=
/kasan-dev/96b2546a-3540-4c08-9817-0468c3146fab%40googlegroups.com</a>.<br =
/>

------=_Part_1518_432675672.1565004128284--

------=_Part_1517_1817126104.1565004128283--
