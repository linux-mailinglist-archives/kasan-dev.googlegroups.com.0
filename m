Return-Path: <kasan-dev+bncBCO25SXBYEMBBJPB567AMGQEKWV66JA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x39.google.com (mail-oa1-x39.google.com [IPv6:2001:4860:4864:20::39])
	by mail.lfdr.de (Postfix) with ESMTPS id 40D5FA6A3DF
	for <lists+kasan-dev@lfdr.de>; Thu, 20 Mar 2025 11:40:39 +0100 (CET)
Received: by mail-oa1-x39.google.com with SMTP id 586e51a60fabf-2a75cda3961sf201707fac.0
        for <lists+kasan-dev@lfdr.de>; Thu, 20 Mar 2025 03:40:39 -0700 (PDT)
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1742467237; x=1743072037; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-sender:mime-version
         :subject:references:in-reply-to:message-id:to:from:date:sender:from
         :to:cc:subject:date:message-id:reply-to;
        bh=5s8Ni3hFCO4gRaukG9HVNVGaRzCmhlt1KQt4eGCDfKQ=;
        b=f8U7rFfAnGv+nQsG5FilHOkIfp1Df2y7Ryo3CtGin1rowlCUqCFMGyGt6ywHxLePgZ
         fY3/NzsngRDKmtcMn/+zcKoZ/8ZxT8F2awIZzb8peqQYfhc0NXLP6kR2D6rkxWScKl/m
         l0QZVJFryHZUuAcR2R0cgWllAcHc9+R5Ce+xE7CFZY6qx9lMC0nEvQrXwZP2U/x5br76
         MtnDNOOG6peGDjHIuojr1zHK+n+BPQOHe46d/ccPS2Ao9c0fGa4RnntWbTutX11t3Anx
         KbeaZ3+PGQPOtWTK0Pf71wIMZFPnftwPlLGn8LveIgu2M0JI4kVj1sG10v4Hcx5qZ1Qm
         Pp8Q==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1742467237; x=1743072037; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-sender:mime-version
         :subject:references:in-reply-to:message-id:to:from:date:from:to:cc
         :subject:date:message-id:reply-to;
        bh=5s8Ni3hFCO4gRaukG9HVNVGaRzCmhlt1KQt4eGCDfKQ=;
        b=ToDIzr2t0uCkqNuwJ/lBG9wfgqvXhxDIMP2ew2UR2O9eH3Tni2y+WJEUC1iqbQws/Z
         65e+gbNT2ahVuWtQ+UlNZguCr41nwHQ/wzG9kFAmurXOnaQQqJdEba1tkw9lOXzDKklt
         jX9CyNZR4msnmYnvAuFoIwD83UA7ZvAieQz39DTRoBD2enBPxqpY+ZPgP/5Pmt2rYEr3
         w0OgAMfT7lYnDOPi1KLIRitXBDjIYqBHUGHOfAj6L2YibQzdAvZf8o6zFE5mhKGWGII0
         bAtas3aK4R1WnbAW/VjtuQ1yDaFoYnW3Cw8B6o74Y+BoTiL1OwW2THU3QDqt1MAKe9DX
         cI2w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1742467237; x=1743072037;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-sender:mime-version:subject:references:in-reply-to
         :message-id:to:from:date:x-beenthere:x-gm-message-state:sender:from
         :to:cc:subject:date:message-id:reply-to;
        bh=5s8Ni3hFCO4gRaukG9HVNVGaRzCmhlt1KQt4eGCDfKQ=;
        b=GOuMA6PrdlfiBfD68i2X6zAOh5lx3QWZlOidDvMoNZ1Yit1krTQlR1T+SxmrK0uhU3
         kR495CkA6gkbFrdK0HHQcjLYrqbf1JB01UGXQVgmKlZGq5OFQgwueGQh+LlKRmm2QhGB
         zLyTM1St4Rxdq8ULvY7qCycQYP61Cr43oLM3zrV6rXmrUZBDL4MN5OhsFHPVp1QhVtjq
         LWrrWsINNbjmQetJW7gP73uwc+7/s7zJvjJq1+HE3tgljZP0Ly4GZNR+grxk25gQS6RY
         CbatXOJ4svMBqJ0R9KgY32Nvovb8koUGxs/RiiIp21c5Rf5INsMH9hTLtnZ5DW7kfNDh
         f3NQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=1; AJvYcCXG0PiHh+HwN4o+6AXcQPZnnp0qKEODNqZL3C52YuXylhgtJy0jP3FB6Mls4q2BBAKSChYFhg==@lfdr.de
X-Gm-Message-State: AOJu0YwKh/Wk/4vPro8fbYvewI2veOlzHMYhaOhTgFOlqmwF1TgSOdM/
	+ihtba464wLxoDyguu8GMzVO9PIKpYxM+jMmTiDd+E0BrFdYTrGN
X-Google-Smtp-Source: AGHT+IHIzp8xuhM0tNSAp/bzbJp2vWBQG/NNer9Xz7IUxcPe7jZ+89RUkA0Zx3IEYobsifkroMD6AQ==
X-Received: by 2002:a05:6870:206:b0:29d:c624:7cad with SMTP id 586e51a60fabf-2c7454275famr4039923fac.3.1742467237600;
        Thu, 20 Mar 2025 03:40:37 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARLLPAIJO0l+MDfq6Y8vytKWcnRInja7p3L1Qc+lXiASFY6URg==
Received: by 2002:a05:6870:9c8f:b0:29f:f56e:68fa with SMTP id
 586e51a60fabf-2c76086ffaels490371fac.2.-pod-prod-09-us; Thu, 20 Mar 2025
 03:40:36 -0700 (PDT)
X-Received: by 2002:a05:6808:2104:b0:3f9:cbc0:7420 with SMTP id 5614622812f47-3feb4b80846mr1787577b6e.27.1742467236465;
        Thu, 20 Mar 2025 03:40:36 -0700 (PDT)
Date: Thu, 20 Mar 2025 03:40:35 -0700 (PDT)
From: ye zhenyu <zhenyuy505@gmail.com>
To: kasan-dev <kasan-dev@googlegroups.com>
Message-Id: <32165ab0-8a47-41b5-8d75-5461414947f2n@googlegroups.com>
In-Reply-To: <CAG_fn=WtE-+HuR9DSYFEYq2=BkwosWwJ0eUMAQWpGJ9JbhFy9g@mail.gmail.com>
References: <3f88fc09-ae66-4a1c-9b87-46928b67be20n@googlegroups.com>
 <CAG_fn=WtE-+HuR9DSYFEYq2=BkwosWwJ0eUMAQWpGJ9JbhFy9g@mail.gmail.com>
Subject: Re: Enable memory tagging in pixel 8a kernel
MIME-Version: 1.0
Content-Type: multipart/mixed; 
	boundary="----=_Part_205966_2063998640.1742467235712"
X-Original-Sender: zhenyuy505@gmail.com
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

------=_Part_205966_2063998640.1742467235712
Content-Type: multipart/alternative; 
	boundary="----=_Part_205967_807648785.1742467235712"

------=_Part_205967_807648785.1742467235712
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable



I am attempting to utilize MTE in the kernel:
Initially, I activate MTE in the phone settings.
Next, I configure the register bit related to MTE to ensure its=20
functionality. I also set the prop in the shell by setprop=20
arm64.memtag.bootctl memtag,memtag-kernel.
Finally, I utilize a kernel module to set/get tags of kernel data; however,=
=20
I consistently receive a value of zero.

The information in my inquiry is obtained through a kernel module. I have=
=20
checked that the registers related to MTE in the manual should not affect=
=20
my use of MTE.

To set the tag, I use the following assembly code:
asm volatile("stg %0, [%0]" : : "r" (tagged_addr) : "memory")=20

To load the tag, I use the following assembly code:
asm volatile("ldg %0, [%0]": "+r" (tagged_addr))=20

another problem is, when I try to clear cache using=20
__asm__ volatile ("tlbi alle1");
the phone will reboot and I can not get any log of kernel.
=E5=9C=A82025=E5=B9=B43=E6=9C=8820=E6=97=A5=E6=98=9F=E6=9C=9F=E5=9B=9B UTC+=
8 17:31:02<Alexander Potapenko> =E5=86=99=E9=81=93=EF=BC=9A

> On Thu, Mar 20, 2025 at 3:03=E2=80=AFAM ye zhenyu <zheny...@gmail.com> wr=
ote:
> >
> > Hello everyone, I have a Pixel 8a and would like to enable MTE in the=
=20
> kernel. However, whenever I try to set or get tags using stg/ldg, it alwa=
ys=20
> returns 0. Does anyone know why and could you please help me? Thank you=
=20
> very much.
> > some registers set :
> > TCR_EL1 : 0x051001f2b5593519 : SCTLR_EL1 : 0x02000d38fc74f99d : MAIR_EL=
1=20
> : 0x0000f4040044f0ff : GCR_EL1 : 0x0000000000010000 : hcr_el2 :=20
> 0x0100030080080001
> > (I can not get the scr_el3)
> > the page table entry of associate address : 0x6800008a2b9707
>
> It is unclear from your report what exactly you are doing.
> Could you please provide the exact steps you perform to build the
> kernel and to get the above register values?
>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/3=
2165ab0-8a47-41b5-8d75-5461414947f2n%40googlegroups.com.

------=_Part_205967_807648785.1742467235712
Content-Type: text/html; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

<div><p style=3D"caret-color: rgb(0, 0, 0); color: rgb(0, 0, 0);">I am atte=
mpting to utilize MTE in the kernel:<br />Initially, I activate MTE in the =
phone settings.<br />Next, I configure the register bit related to MTE to e=
nsure its functionality. I also set the prop in the shell by=C2=A0<span sty=
le=3D"font-family: monospace; font-size: 11.7px;">setprop arm64.memtag.boot=
ctl memtag,memtag-kernel.</span><br />Finally, I utilize a kernel module to=
 set/get tags of kernel data; however, I consistently receive a value of ze=
ro.</p><p style=3D"caret-color: rgb(0, 0, 0); color: rgb(0, 0, 0);">The inf=
ormation in my inquiry is obtained through a kernel module. I have checked =
that the registers related to MTE in the manual should not affect my use of=
 MTE.</p><p style=3D"caret-color: rgb(0, 0, 0); color: rgb(0, 0, 0);">To se=
t the tag, I use the following assembly code:</p><span style=3D"caret-color=
: rgb(0, 0, 0); color: rgb(0, 0, 0);">asm volatile("stg %0, [%0]" : : "r" (=
tagged_addr) : "memory")
</span><p style=3D"caret-color: rgb(0, 0, 0); color: rgb(0, 0, 0);">To load=
 the tag, I use the following assembly code:</p><span style=3D"caret-color:=
 rgb(0, 0, 0); color: rgb(0, 0, 0);">asm volatile("ldg %0, [%0]": "+r" (tag=
ged_addr))=C2=A0</span><br /></div><div><span style=3D"caret-color: rgb(0, =
0, 0); color: rgb(0, 0, 0);"><br /></span></div><div><font color=3D"#000000=
"><span style=3D"caret-color: rgb(0, 0, 0);">another problem is, when I try=
 to clear cache using=C2=A0</span></font></div><div>__asm__ volatile ("tlbi=
 alle1");</div><div>the phone will reboot and I can not get any log of kern=
el.</div><div class=3D"gmail_quote"><div dir=3D"auto" class=3D"gmail_attr">=
=E5=9C=A82025=E5=B9=B43=E6=9C=8820=E6=97=A5=E6=98=9F=E6=9C=9F=E5=9B=9B UTC+=
8 17:31:02&lt;Alexander Potapenko> =E5=86=99=E9=81=93=EF=BC=9A<br/></div><b=
lockquote class=3D"gmail_quote" style=3D"margin: 0 0 0 0.8ex; border-left: =
1px solid rgb(204, 204, 204); padding-left: 1ex;">On Thu, Mar 20, 2025 at 3=
:03=E2=80=AFAM ye zhenyu &lt;<a href data-email-masked rel=3D"nofollow">zhe=
ny...@gmail.com</a>&gt; wrote:
<br>&gt;
<br>&gt; Hello everyone, I have a Pixel 8a and would like to enable MTE in =
the kernel. However, whenever I try to set or get tags using stg/ldg, it al=
ways returns 0. Does anyone know why and could you please help me? Thank yo=
u very much.
<br>&gt; some registers set :
<br>&gt;  TCR_EL1 : 0x051001f2b5593519 : SCTLR_EL1 : 0x02000d38fc74f99d : M=
AIR_EL1 : 0x0000f4040044f0ff : GCR_EL1 : 0x0000000000010000 : hcr_el2 : 0x0=
100030080080001
<br>&gt; (I can not get the scr_el3)
<br>&gt; the page table entry of associate address : 0x6800008a2b9707
<br>
<br>It is unclear from your report what exactly you are doing.
<br>Could you please provide the exact steps you perform to build the
<br>kernel and to get the above register values?
<br></blockquote></div>

<p></p>

-- <br />
You received this message because you are subscribed to the Google Groups &=
quot;kasan-dev&quot; group.<br />
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to <a href=3D"mailto:kasan-dev+unsubscribe@googlegroups.com">kasan-dev=
+unsubscribe@googlegroups.com</a>.<br />
To view this discussion visit <a href=3D"https://groups.google.com/d/msgid/=
kasan-dev/32165ab0-8a47-41b5-8d75-5461414947f2n%40googlegroups.com?utm_medi=
um=3Demail&utm_source=3Dfooter">https://groups.google.com/d/msgid/kasan-dev=
/32165ab0-8a47-41b5-8d75-5461414947f2n%40googlegroups.com</a>.<br />

------=_Part_205967_807648785.1742467235712--

------=_Part_205966_2063998640.1742467235712--
