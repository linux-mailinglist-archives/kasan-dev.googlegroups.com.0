Return-Path: <kasan-dev+bncBCR4DL77YAGRBNEZSSVQMGQEJISZF3Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53a.google.com (mail-pg1-x53a.google.com [IPv6:2607:f8b0:4864:20::53a])
	by mail.lfdr.de (Postfix) with ESMTPS id 4E2E47FACA6
	for <lists+kasan-dev@lfdr.de>; Mon, 27 Nov 2023 22:40:06 +0100 (CET)
Received: by mail-pg1-x53a.google.com with SMTP id 41be03b00d2f7-5bd0c909c50sf4591260a12.3
        for <lists+kasan-dev@lfdr.de>; Mon, 27 Nov 2023 13:40:06 -0800 (PST)
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1701121205; x=1701726005; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-sender:mime-version
         :subject:message-id:to:from:date:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=ApDD/2ENpAfoV4H3wvF2VrB6yaMBAui9hQIN7fniQJ4=;
        b=JmVP/C4LCUYOSXdMUKmaU9g7qpOB80QEn/kc/sejhPNVVv5OQ5xRNn5SXrCRvu3Lw0
         RDpO3FM52HpSGl5ceQr4e/7YOkdkuwCxgEo0gQ4NVNi5JKYTvGmQr+hw3ZUurG331k62
         iuoFUA47VyQH23KWMS1p24UKm8yXcE47Cko/k59YVdQlnCsP7uJcUKF8BVMsfHY418Ta
         fsfVYwo9IaVyhDOZPmKp+frR/03c8zVD3Eq0MADj8PnxjzCSDnVXHT1nU9NF/AXsFVPL
         Yv5MrZlL874XkF3V9muBU+m5LD97g9yCXBENM6yVTcfJ3Ch6mLvcfQjRMO8ArZGri+A2
         RlKg==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1701121205; x=1701726005; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-sender:mime-version
         :subject:message-id:to:from:date:from:to:cc:subject:date:message-id
         :reply-to;
        bh=ApDD/2ENpAfoV4H3wvF2VrB6yaMBAui9hQIN7fniQJ4=;
        b=nJC50LTbZnQhfFpnPK6x8Gl9ge6iz1k5rprVw7VRVY+unB4wKd9RgwHIDPlybLvG3D
         IyD2AC/CcigUslgUYtwttM2VXWh+23klmHonv2lIs4HA5pDucEMgmRvxzC7yyPJWvQI3
         0WrXCwJBgFZ/cdRvk2aOTK6NtMpg6rkofAOoJRTcaiAG/vHc0+2DDaNjionCRJWH2JPZ
         bQm0ZUvsRGTdi/VTeSaiTIPFcFmkMOAzl6NCLEOhUjCAIXwHY3KCjecRyooxzT1wCPjf
         achb9imb2Sx0HXVZArkHSbIVO5AVv9dpG91GCUsYCFqdxN4pccYPa0ywZkoJGVaoVXB5
         MXzQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1701121205; x=1701726005;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-sender:mime-version:subject:message-id:to:from:date
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=ApDD/2ENpAfoV4H3wvF2VrB6yaMBAui9hQIN7fniQJ4=;
        b=vf2+kle3ChuecH8Tf2hoR0OFTjAGLP68F79K748mwhAdOwHF4LVZYnfwzmsN5aZIKY
         bsL6F99d9+JF7AkmCvknVMq8xq+Me2h4j9Oj9I5ij/AGkkjaWxOMedbidulBD2XhQ7ZE
         zQ1EYomn3OvzO+Bfa+JFGWYIuOAIOxrh+FNzBM0ZFm1zIP/wM8EOjNrMVRiLwtq37OZv
         71DNJPc3KLaEl43IK5O0ZI2137hVMj2e2YOFpJNZgMGjQGKz90O5x7HgRhwL9Zh5m7iw
         RoUCycCDI6U4PCw7JZRQ+G8URX6b0GWyG9Xb9wg/k994ns3JYgmuJr8NQsXn+YUZWFzN
         qsFA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YxgOTYEi5GRqoZM7MGYoXorl+6i6mTSWLtPPNe307f5gU5rIFyx
	+d7y2R+lEpinCssGKaibJiw=
X-Google-Smtp-Source: AGHT+IFe5InvUcX7W5LiNgiXFhKpTYLFxa288s8Y/BFUsy/etqa/hA31hHYx/XlJYGpRqk7m2OKoqQ==
X-Received: by 2002:a05:6a20:7f86:b0:187:f2f7:2383 with SMTP id d6-20020a056a207f8600b00187f2f72383mr14271415pzj.45.1701121204618;
        Mon, 27 Nov 2023 13:40:04 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6a00:1d1d:b0:6cb:ba06:e0f8 with SMTP id
 a29-20020a056a001d1d00b006cbba06e0f8ls3345734pfx.1.-pod-prod-01-us; Mon, 27
 Nov 2023 13:40:03 -0800 (PST)
X-Received: by 2002:a05:6a00:399c:b0:6c0:ec5b:bb2d with SMTP id fi28-20020a056a00399c00b006c0ec5bbb2dmr3161696pfb.2.1701121203533;
        Mon, 27 Nov 2023 13:40:03 -0800 (PST)
Date: Mon, 27 Nov 2023 13:40:02 -0800 (PST)
From: Nguyet Edmondson <edmondsonnguyet@gmail.com>
To: kasan-dev <kasan-dev@googlegroups.com>
Message-Id: <55cc49cb-a1ac-4df7-b4f5-b768cfdec4a1n@googlegroups.com>
Subject: Proteus VFX Redshift In Production
MIME-Version: 1.0
Content-Type: multipart/mixed; 
	boundary="----=_Part_144932_852836513.1701121202706"
X-Original-Sender: edmondsonnguyet@gmail.com
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

------=_Part_144932_852836513.1701121202706
Content-Type: multipart/alternative; 
	boundary="----=_Part_144933_681174584.1701121202706"

------=_Part_144933_681174584.1701121202706
Content-Type: text/plain; charset="UTF-8"

How Proteus VFX Uses Redshift to Create Stunning Visual EffectsProteus VFX 
is a leading visual effects studio that specializes in creating realistic 
and immersive CGI for films, TV shows, commercials, and games. Proteus VFX 
has worked on projects such as The Matrix 4, Avatar 2, Star Wars: The Rise 
of Skywalker, and Cyberpunk 2077. In this article, we will explore how 
Proteus VFX uses Redshift, the world's fastest GPU-accelerated renderer, to 
achieve stunning results in production.
What is Redshift?Redshift is a powerful and flexible rendering software 
that leverages the power of GPUs to deliver fast and high-quality images. 
Redshift supports a variety of features such as ray tracing, global 
illumination, volumetrics, subsurface scattering, motion blur, depth of 
field, and more. Redshift also integrates seamlessly with popular 3D 
applications such as Maya, Cinema 4D, Houdini, Blender, and Unreal Engine.

Proteus VFX Redshift in Production
Download File https://urlgoal.com/2wGKzJ


Learn more about Redshift here.Why Proteus VFX Chooses Redshift?Proteus VFX 
has been using Redshift since 2018 and has seen significant improvements in 
their workflow and output quality. Here are some of the reasons why Proteus 
VFX chooses Redshift:
Speed: Redshift is up to 10 times faster than other renderers, thanks to 
its GPU-based architecture and smart sampling techniques. This allows 
Proteus VFX to iterate faster and meet tight deadlines.Scalability: 
Redshift can handle complex scenes with millions of polygons and thousands 
of lights without compromising performance or quality. This enables Proteus 
VFX to create large-scale environments and detailed characters with 
ease.Versatility: Redshift supports a wide range of shading models and 
materials, including physically based rendering (PBR), hair and fur, skin, 
cloth, metal, glass, and more. This gives Proteus VFX the creative freedom 
to achieve any look they want.Compatibility: Redshift works seamlessly with 
Proteus VFX's pipeline and tools, such as Maya, Houdini, Nuke, Substance 
Painter, ZBrush, and Photoshop. This ensures a smooth and consistent 
workflow across different stages of production.How Proteus VFX Uses 
Redshift in Production?Proteus VFX uses Redshift for all their rendering 
needs, from previsualization to final delivery. Here are some examples of 
how Proteus VFX uses Redshift in production:
Previsualization: Proteus VFX uses Redshift to create quick and realistic 
previews of their scenes and animations. This helps them to test different 
ideas, refine their concepts, and communicate their vision to the clients 
and directors.Lighting: Proteus VFX uses Redshift to create realistic and 
dynamic lighting for their scenes. They use features such as area lights, 
image-based lighting (IBL), physical sun and sky system, portals, light 
linking, light groups, and AOVs to achieve the desired mood and 
atmosphere.Shading: Proteus VFX uses Redshift to create rich and complex 
materials for their assets. They use features such as layered shaders, 
node-based shading network, custom AOVs, displacement maps, normal maps, 
bump maps, occlusion maps, roughness maps,and more to add realism and 
detail to their models.Volumetrics: Proteus VFX uses Redshift to create 
stunning volumetric effects such as smoke, fire,fog, clouds, dust, and 
explosions. They use features such as volume shader,volume 
scattering,volume emission,volume ramps,


 35727fac0c


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/55cc49cb-a1ac-4df7-b4f5-b768cfdec4a1n%40googlegroups.com.

------=_Part_144933_681174584.1701121202706
Content-Type: text/html; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

How Proteus VFX Uses Redshift to Create Stunning Visual EffectsProteus VFX =
is a leading visual effects studio that specializes in creating realistic a=
nd immersive CGI for films, TV shows, commercials, and games. Proteus VFX h=
as worked on projects such as The Matrix 4, Avatar 2, Star Wars: The Rise o=
f Skywalker, and Cyberpunk 2077. In this article, we will explore how Prote=
us VFX uses Redshift, the world's fastest GPU-accelerated renderer, to achi=
eve stunning results in production.<div>What is Redshift?Redshift is a powe=
rful and flexible rendering software that leverages the power of GPUs to de=
liver fast and high-quality images. Redshift supports a variety of features=
 such as ray tracing, global illumination, volumetrics, subsurface scatteri=
ng, motion blur, depth of field, and more. Redshift also integrates seamles=
sly with popular 3D applications such as Maya, Cinema 4D, Houdini, Blender,=
 and Unreal Engine.</div><div><br /></div><div>Proteus VFX Redshift in Prod=
uction</div><div>Download File https://urlgoal.com/2wGKzJ<br /><br /><br />=
Learn more about Redshift here.Why Proteus VFX Chooses Redshift?Proteus VFX=
 has been using Redshift since 2018 and has seen significant improvements i=
n their workflow and output quality. Here are some of the reasons why Prote=
us VFX chooses Redshift:</div><div>Speed: Redshift is up to 10 times faster=
 than other renderers, thanks to its GPU-based architecture and smart sampl=
ing techniques. This allows Proteus VFX to iterate faster and meet tight de=
adlines.Scalability: Redshift can handle complex scenes with millions of po=
lygons and thousands of lights without compromising performance or quality.=
 This enables Proteus VFX to create large-scale environments and detailed c=
haracters with ease.Versatility: Redshift supports a wide range of shading =
models and materials, including physically based rendering (PBR), hair and =
fur, skin, cloth, metal, glass, and more. This gives Proteus VFX the creati=
ve freedom to achieve any look they want.Compatibility: Redshift works seam=
lessly with Proteus VFX's pipeline and tools, such as Maya, Houdini, Nuke, =
Substance Painter, ZBrush, and Photoshop. This ensures a smooth and consist=
ent workflow across different stages of production.How Proteus VFX Uses Red=
shift in Production?Proteus VFX uses Redshift for all their rendering needs=
, from previsualization to final delivery. Here are some examples of how Pr=
oteus VFX uses Redshift in production:</div><div>Previsualization: Proteus =
VFX uses Redshift to create quick and realistic previews of their scenes an=
d animations. This helps them to test different ideas, refine their concept=
s, and communicate their vision to the clients and directors.Lighting: Prot=
eus VFX uses Redshift to create realistic and dynamic lighting for their sc=
enes. They use features such as area lights, image-based lighting (IBL), ph=
ysical sun and sky system, portals, light linking, light groups, and AOVs t=
o achieve the desired mood and atmosphere.Shading: Proteus VFX uses Redshif=
t to create rich and complex materials for their assets. They use features =
such as layered shaders, node-based shading network, custom AOVs, displacem=
ent maps, normal maps, bump maps, occlusion maps, roughness maps,and more t=
o add realism and detail to their models.Volumetrics: Proteus VFX uses Reds=
hift to create stunning volumetric effects such as smoke, fire,fog, clouds,=
 dust, and explosions. They use features such as volume shader,volume scatt=
ering,volume emission,volume ramps,</div><div><br /></div><div><br /></div>=
<div>=C2=A035727fac0c</div><div><br /></div><div><br /></div>

<p></p>

-- <br />
You received this message because you are subscribed to the Google Groups &=
quot;kasan-dev&quot; group.<br />
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to <a href=3D"mailto:kasan-dev+unsubscribe@googlegroups.com">kasan-dev=
+unsubscribe@googlegroups.com</a>.<br />
To view this discussion on the web visit <a href=3D"https://groups.google.c=
om/d/msgid/kasan-dev/55cc49cb-a1ac-4df7-b4f5-b768cfdec4a1n%40googlegroups.c=
om?utm_medium=3Demail&utm_source=3Dfooter">https://groups.google.com/d/msgi=
d/kasan-dev/55cc49cb-a1ac-4df7-b4f5-b768cfdec4a1n%40googlegroups.com</a>.<b=
r />

------=_Part_144933_681174584.1701121202706--

------=_Part_144932_852836513.1701121202706--
