Return-Path: <kasan-dev+bncBC7M5BFO7YCRBFW4SKYAMGQENO2D74Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x440.google.com (mail-pf1-x440.google.com [IPv6:2607:f8b0:4864:20::440])
	by mail.lfdr.de (Postfix) with ESMTPS id B046288F349
	for <lists+kasan-dev@lfdr.de>; Thu, 28 Mar 2024 00:39:04 +0100 (CET)
Received: by mail-pf1-x440.google.com with SMTP id d2e1a72fcca58-6e6b285aaa4sf429940b3a.2
        for <lists+kasan-dev@lfdr.de>; Wed, 27 Mar 2024 16:39:04 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1711582743; cv=pass;
        d=google.com; s=arc-20160816;
        b=VqqeEOS3B+PvdiD4QCpdnVsolcns86nE3sGd+e+quUuaqdL1AutvedGUTlBfRIjVZS
         uhsTbCxJnNfOHzPKfWZzbrwEBzIFb6zho5j+zUZlXzLVsyUar40dTKW+yGSCqneYHOu8
         9v+13ygX6d+TYhC5rqR+FMXFvIvNWBL5XeDTfqjusSzoqXMHSXgzWRoKyzCu+LbL3ltx
         rjjOOCg6d4tKzDXzstV51rO4wjyDkcstE2pTswWT7Ns4SM5TaADPIm0Xmba6nJODo5cx
         3vn5XIMyqXUBhvmuiYzAcl4/AYBTpyU9IPqYeyr3r8cW1qGR4VKTq/ejb4RNKGhHdUgH
         v8Vg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=o1rYwruo1vQDqZSRTqIntdIXFqOb6tDT2v1js4wYO/Q=;
        fh=Ycb6cBRY7JDRbOViwf7UJTRFjRKXi8a+D76Vk/nSA3o=;
        b=0MNZDOo5PsmywLBl3embbjoEHirTgxZlPJ3ygMq3FzGOzt8LcnLLucQ0z58MwJmfak
         mBTe2S969JRzk1RKeKxhR11tEqsc4eHcHYjtIWu8q06sOM4N40TS6sx6IkOykySks4Z8
         Eqi/xDxAfCSp04tKDUO3G2QPYxjxXaj2pdtGkbTE4e/gxMciT11sgHM8Cd58DRROB+fG
         N58udcTGATzLogT3jYyWX9ydSLxopAbsV/p4xbhhGksp+EZ7CpW4Bvv8aploAH1a5w6A
         cGh3JJNj8wum6GYKd1yd3XvZjzE2775/GxojGuZYMTjEmJRGRggwm6bXJ/SSCwx26+l6
         nhDw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=B51L2mO9;
       spf=pass (google.com: domain of groeck7@gmail.com designates 2607:f8b0:4864:20::62e as permitted sender) smtp.mailfrom=groeck7@gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1711582743; x=1712187543; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-transfer-encoding
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:from:to:cc:subject:date:message-id:reply-to;
        bh=o1rYwruo1vQDqZSRTqIntdIXFqOb6tDT2v1js4wYO/Q=;
        b=nXJqs3EdXBJ6Nb0n8UrIOIrwab1GO72LZYN+OT6L7CVpGqL5jgPmylr0GJO/q/f7Vp
         Qbcbf8aXuBr2ivQwlwaZGWmNn7VikYAmwKQlVOxbpNQitqQJ3MmiDaoxeeRVGcZMtfAI
         c6xVdC5fQylpHj7WoKVc1g0YWWSgucxVDG/55Ou+fXE8RJf8LZ3T9H4e+49f73Swwzi/
         Dvi1AZ3ZRG6nBht7/pLloCp6XzpxJBwt9PJhiUCEMhQQCUYOn+2FOedGVSU6KcKB22ki
         Z3+GAsg58i0m5/EoyRdQLcpNVY+KRRfvsNi8tlf+cs4ZqlYMUceKA+GuwbAYSBfiG9YP
         njIw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1711582743; x=1712187543;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:x-beenthere
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=o1rYwruo1vQDqZSRTqIntdIXFqOb6tDT2v1js4wYO/Q=;
        b=T+kCyYTSv/1iP5rl6/DGVh6unWViEWeqiTqoMD6C+8l7uk259xQfzMRZZ3AnBrDzrd
         G8zGd7bL0gKA2YKnm4wDnN0Bkrb/aQJ+J2sX8qQPHJpKuB6k8iTiwarCmGCcBLORpCvg
         LXvdfkVQFpvI++ItYxDX6z2LgxC40qDfg6v7/qmwiukzTF+6G3b+pTrAG6dvVAKlV3kk
         5vcTyAhtyow2UKFNcnmVI81IMegu+eBKdkEd9PE+ZUlEAk82nZzHDPu5tw2nqTURI+Sn
         NnlMuNEu+/28SMHeR790/n6HzxdvqKItZjU04vRbijNM2fkpThrT6MLAO4BW95dT9VFq
         WSEA==
X-Forwarded-Encrypted: i=2; AJvYcCVr0iKt5iKS5Lghsbrt0hWkcSGPaYVMjNR2Vl53K1HnThh9D+cRVBd8DfzSZcxehPIGAYysDluldv2FU5kV4ctQXtUjTt6Tzg==
X-Gm-Message-State: AOJu0Yw9GgnLDoT/JZlgy3rzT1oZk4GzPLw1lrSoHqtp2nd1tXwtAKIp
	ogwUXxLgwObw2TEkPEB0ZwUva0Sygbxqena2HhFdbvk3/nKxQwa4
X-Google-Smtp-Source: AGHT+IHqfR38V4tXwfIVZgLa1i4RlfEPdfpZVwdN/WoOtJJZTFfZJ5xd8cnGgRzHpZWs5gDEIIXUjQ==
X-Received: by 2002:a05:6a21:3990:b0:1a3:6a71:8282 with SMTP id ad16-20020a056a21399000b001a36a718282mr2004102pzc.0.1711582742935;
        Wed, 27 Mar 2024 16:39:02 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:9a8b:b0:2a0:1a3d:df75 with SMTP id
 e11-20020a17090a9a8b00b002a01a3ddf75ls213027pjp.2.-pod-prod-05-us; Wed, 27
 Mar 2024 16:39:01 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVKvHXjSMnWRbcL3H/yHZk/oSWbJb9cnF9yr65ehPCPdPm6Y28VDbjv++K5nrYtTpY8GErDube1mfH7iSFG5J5pyskq7WmjK8ggiQ==
X-Received: by 2002:a17:90a:8a98:b0:29e:c3d:c3fc with SMTP id x24-20020a17090a8a9800b0029e0c3dc3fcmr1188379pjn.18.1711582741516;
        Wed, 27 Mar 2024 16:39:01 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1711582741; cv=none;
        d=google.com; s=arc-20160816;
        b=ZnkrDx/DY5+VCL/nq1tHVx03eEXpPUf1QJ+6t7p3s9klxc5sH5HrtxqGj2QYNEXkgV
         g27SM7yqrTv7b0iDeTWWHUmRXTLDntdljxeKE40PImaz5Z2RHcuUzFU+3qhO/9+SJ+UY
         nitxdJCFp57a20NDy5RrhNM6v+PnCs+HU7EI4Ye2pKSaqUrUftdpZv6tSLKAOFfFYYnY
         t9wZqWQroDFMzQ77TC5V6Gg2vCbcqbNES3NLS4B36Li4DXLO6aG5uq4zVSJYGfJdYLj6
         L6zgbjGkNV++xhEbyBk/vuYpWnzvxDo+8p2WSa6fFFM0yd1B7zsZyK9qqF4hBaNb3qpm
         BfHA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-transfer-encoding:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=eT3BGCrQv0KvikApGDS0rW7CAhCymZWIvFUGG2zxp2g=;
        fh=+wd8+yE+XZ9aNry2XLMjYC40kk9pGe5pV4ji56ZbTe4=;
        b=GC7XQespDbYeGE+FqZsTQ7EbSlf5oWM6bc48Z2JKXBxngowaPUybeYLXpUEFWsOPki
         RfXPKGQvREDFTlSadHplhfPPz4tZY80SkQg/q5tLwrtuaUnRWSBx/K7D9Yl9v0Alb2la
         dhE6g0JpBFylUAXwEdUgQTaa3z4XD2xCR5CE9dcMzXlBGvFniUZBhL/jvuY0jl6KEKR3
         MjfaBLI+bWhPsDJg29U42gXw5WMaUo1fwSscfaZ8YGoUpSWdzW7PgNxojrtz9/8RNXeb
         sDMJJd98vJFIzunZ8vTcMR0W75Si7YQfc652KYK1sUOj5XEknNxfFaPf8ldHkQhwJn0e
         VPDQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=B51L2mO9;
       spf=pass (google.com: domain of groeck7@gmail.com designates 2607:f8b0:4864:20::62e as permitted sender) smtp.mailfrom=groeck7@gmail.com
Received: from mail-pl1-x62e.google.com (mail-pl1-x62e.google.com. [2607:f8b0:4864:20::62e])
        by gmr-mx.google.com with ESMTPS id h15-20020a17090acf0f00b002a1f54bb833si136803pju.0.2024.03.27.16.39.01
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 27 Mar 2024 16:39:01 -0700 (PDT)
Received-SPF: pass (google.com: domain of groeck7@gmail.com designates 2607:f8b0:4864:20::62e as permitted sender) client-ip=2607:f8b0:4864:20::62e;
Received: by mail-pl1-x62e.google.com with SMTP id d9443c01a7336-1e0d82c529fso3752715ad.2
        for <kasan-dev@googlegroups.com>; Wed, 27 Mar 2024 16:39:01 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCUyr4tPakaD7LdaNLRAxkkl6Vkx/a2HRrkS4VL6wQJf8VfTP3Zxv5hTzBz2VhZjBtPaUP144M8+bz+8qyHDPkyDEIcUTcaCX58Lmw==
X-Received: by 2002:a17:902:e88b:b0:1dc:b73b:ec35 with SMTP id w11-20020a170902e88b00b001dcb73bec35mr1220112plg.4.1711582741011;
        Wed, 27 Mar 2024 16:39:01 -0700 (PDT)
Received: from server.roeck-us.net ([2600:1700:e321:62f0:329c:23ff:fee3:9d7c])
        by smtp.gmail.com with ESMTPSA id j8-20020a170902da8800b001e205884ac6sm98261plx.20.2024.03.27.16.38.59
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 27 Mar 2024 16:39:00 -0700 (PDT)
Sender: Guenter Roeck <groeck7@gmail.com>
Date: Wed, 27 Mar 2024 16:38:58 -0700
From: Guenter Roeck <linux@roeck-us.net>
To: Xi Ruoyao <xry111@xry111.site>
Cc: loongarch@lists.linux.dev, Huacai Chen <chenhuacai@kernel.org>,
	WANG Xuerui <kernel@xen0n.name>,
	Alexander Potapenko <glider@google.com>,
	Marco Elver <elver@google.com>, Dmitry Vyukov <dvyukov@google.com>,
	kasan-dev@googlegroups.com
Subject: Re: Kernel BUG with loongarch and CONFIG_KFENCE and CONFIG_DEBUG_SG
Message-ID: <19c0ec82-59ce-4f46-9a38-cdca059e8867@roeck-us.net>
References: <c352829b-ed75-4ffd-af6e-0ea754e1bf3d@roeck-us.net>
 <4d2373e3f0694fd02137a72181d054ee2ebcca45.camel@xry111.site>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <4d2373e3f0694fd02137a72181d054ee2ebcca45.camel@xry111.site>
X-Original-Sender: linux@roeck-us.net
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=B51L2mO9;       spf=pass
 (google.com: domain of groeck7@gmail.com designates 2607:f8b0:4864:20::62e as
 permitted sender) smtp.mailfrom=groeck7@gmail.com
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

On Thu, Mar 28, 2024 at 03:33:03AM +0800, Xi Ruoyao wrote:
> On Wed, 2024-03-27 at 12:11 -0700, Guenter Roeck wrote:
> > Hi,
> >=20
> > when enabling both CONFIG_KFENCE and CONFIG_DEBUG_SG, I get the followi=
ng
> > backtraces when running loongarch images in qemu.
> >=20
> > [=C2=A0=C2=A0=C2=A0 2.496257] kernel BUG at include/linux/scatterlist.h=
:187!
> > ...
> > [=C2=A0=C2=A0=C2=A0 2.501925] Call Trace:
> > [=C2=A0=C2=A0=C2=A0 2.501950] [<9000000004ad59c4>] sg_init_one+0xac/0xc=
0
> > [=C2=A0=C2=A0=C2=A0 2.502204] [<9000000004a438f8>] do_test_kpp+0x278/0x=
6e4
> > [=C2=A0=C2=A0=C2=A0 2.502353] [<9000000004a43dd4>] alg_test_kpp+0x70/0x=
f4
> > [=C2=A0=C2=A0=C2=A0 2.502494] [<9000000004a41b48>] alg_test+0x128/0x690
> > [=C2=A0=C2=A0=C2=A0 2.502631] [<9000000004a3d898>] cryptomgr_test+0x20/=
0x40
> > [=C2=A0=C2=A0=C2=A0 2.502775] [<90000000041b4508>] kthread+0x138/0x158
> > [=C2=A0=C2=A0=C2=A0 2.502912] [<9000000004161c48>] ret_from_kernel_thre=
ad+0xc/0xa4
> >=20
> > The backtrace is always similar but not exactly the same. It is always
> > triggered from cryptomgr_test, but not always from the same test.
> >=20
> > Analysis shows that with CONFIG_KFENCE active, the address returned fro=
m
> > kmalloc() and friends is not always below vm_map_base. It is allocated =
by
> > kfence_alloc() which at least sometimes seems to get its memory from an
> > address space above vm_map_base. This causes virt_addr_valid() to retur=
n
> > false for the affected objects.
>=20
> Oops, Xuerui has been haunted by some "random" kernel crashes only
> occurring with CONFIG_KFENCE=3Dy for months but we weren't able to triage
> the issue:
>=20
> https://github.com/loongson-community/discussions/issues/34
>=20
> Maybe the same issue or not.
>=20

Good question. I suspect it might at least be related.

Maybe people can try the patch below. It seems to fix the probem for me.
It might well be, though, that there are other instances in the code
where the same or a similar check is needed.

Thanks,
Guenter

---
diff --git a/arch/loongarch/mm/mmap.c b/arch/loongarch/mm/mmap.c
index a9630a81b38a..89af7c12e8c0 100644
--- a/arch/loongarch/mm/mmap.c
+++ b/arch/loongarch/mm/mmap.c
@@ -4,6 +4,7 @@
  */
 #include <linux/export.h>
 #include <linux/io.h>
+#include <linux/kfence.h>
 #include <linux/memblock.h>
 #include <linux/mm.h>
 #include <linux/mman.h>
@@ -111,6 +112,9 @@ int __virt_addr_valid(volatile void *kaddr)
 {
 	unsigned long vaddr =3D (unsigned long)kaddr;
=20
+	if (is_kfence_address((void *)kaddr))
+		return 1;
+
 	if ((vaddr < PAGE_OFFSET) || (vaddr >=3D vm_map_base))
 		return 0;
=20

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/19c0ec82-59ce-4f46-9a38-cdca059e8867%40roeck-us.net.
