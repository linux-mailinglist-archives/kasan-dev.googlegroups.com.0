Return-Path: <kasan-dev+bncBCKPFB7SXUERBM6J63CAMGQEZUEC47Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x3b.google.com (mail-oa1-x3b.google.com [IPv6:2001:4860:4864:20::3b])
	by mail.lfdr.de (Postfix) with ESMTPS id 11C3AB25FBE
	for <lists+kasan-dev@lfdr.de>; Thu, 14 Aug 2025 10:56:22 +0200 (CEST)
Received: by mail-oa1-x3b.google.com with SMTP id 586e51a60fabf-30ccebab467sf1451060fac.2
        for <lists+kasan-dev@lfdr.de>; Thu, 14 Aug 2025 01:56:22 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1755161780; cv=pass;
        d=google.com; s=arc-20240605;
        b=TV/LdfdvDW483thd/frx/I+oHgKe1pSiX6bF7/Z2FJLJ1GZNJ89F74zB3qGDpJmuVu
         3I5lB+Nu4PIscOuHSk8+07vcjLc3NZkC3rjnIu6X8mMZP28bw4vtBzEJj6MnH2EH5e9M
         +YoGUfkpdRelu+enwlwbk0AU0WflAczrP5dQe9fE3hbQaPRKqr3XuyADLCxmwIk84YXo
         O6QxBcn2x2nvujncst6B31p3ea2MY0oyVvudtF1tHmQ7Bouq0y0ggUfmMzAfWTqmW3XK
         luZIvRNhquqIpTbBasDA+2Lh+fLQGKf4evVV+Y09jcFSkJwewfD/QE7owembUL+CoRck
         hkmw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:dkim-signature;
        bh=hlIY9A+O7j+4popwOLCIM+9kBIAb+gmvMFUcZNxPRNE=;
        fh=7epUr3Pa0Fyza+HAzUpO/qWBgcHI8xndfksIEsDmyv4=;
        b=gpBYb5R6kpfTBRSj2Rr1hOW16FLN5nerVMacFu6eomIaRF8Gf9bgwUvLP9B2vIYKRG
         3NTfQm3RF/C9gSVwEYg8tqKX/IRz9uq3rN4xWhh1tQnC1I9tWuxnEfWK3FBHdxGPbe7M
         NRmKQa/7LSms0wGgtCOKyRFdSI7h6qv7FiWQqUsJCrzqgYjARMewwp1q+EiaQpKQZUZv
         GtEwWr/D14h+Tvx1hs5fWcMcajMeQd1jtS2pqyX2gCnUsC/i3p+XvM2be2fYORFqfmMD
         mAXdEEPx9DZ28ZZ5sje38L/priNRZYfFsqOp/OCSrae2/kWuM5OBuR/07HpR5yyOnW61
         30aA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=TIGQNDNh;
       spf=pass (google.com: domain of bhe@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=bhe@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1755161780; x=1755766580; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:from:to:cc:subject
         :date:message-id:reply-to;
        bh=hlIY9A+O7j+4popwOLCIM+9kBIAb+gmvMFUcZNxPRNE=;
        b=v/pefEz5u0qG3X8tF399jsupfJSip5WwM1EqNXVpMUso8gMTlUjuIQF/bndunCWJV2
         1HvENc/o+lUDQ+4pNBa+dblESOYdSCFbWunNF90lyZcIM+i75VMjPhH2/VE3NKllPNDn
         AL8893gBSa9w4gY6+Uaxcd7NLXNEULUgogSdaV3bXdHsTsrOy48HVOt2I4Na5qF3X41/
         JCL+1408vv445qcMhtoochBJkp1K0D+Nocu+O3uG3bSL7pHx39IsJy9J3AJB+GiAFHPu
         I2AuUeUwuv/NzUMIbbYRvgZgPpzg9kqeYlzA2pXrluFWL2XZ7PkBDxs9tPFNhiO/otjx
         dZCw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1755161780; x=1755766580;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:x-beenthere
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=hlIY9A+O7j+4popwOLCIM+9kBIAb+gmvMFUcZNxPRNE=;
        b=cuUAcDhwOL4+Hr3QnQdp6v7Ba/cn59+HS+QmScb5bkC1WuSiC+VlHpOsIwMQ1DVsAT
         JVZdqv+LklPHudNtPD1XMDBVMJdKh5bzn1i/vOKNJ+AA/wVexjnRXidGxA8wKP/GGx7C
         Jb7GptakN4+bKoJx6mLW7WuARN+4gJ0l9ofv+Z2gYqDG+VpksLQNupIwwO92cZpCzAPx
         ZDFu8XeRSkXjnFfdGAW+LKMktwAcRnsO0Aq1SOCwkZVfjCe85ba0j9XUT6qbuZMqvMlP
         QKbeWrNA/fcaFPop+/p+e+4ZNsInTH/l7VW6quSGxOePqbzTQd3Mzpa49y2SWS6X27wQ
         VpFg==
X-Forwarded-Encrypted: i=2; AJvYcCWM5Fa3Sy85yK0w7BIF8xodNItsiICCHsEeO7XNjT+oSEFqOPNx0qphW0kNBvl9FVdKuX1nkQ==@lfdr.de
X-Gm-Message-State: AOJu0Yw7qts4s8cMureC5ACztxIp1G9IF8LxzJ40r42tGSnGvytCJa/4
	PJWkbHqreUETDnsusOCKnzCBOWExULaYLp9Ygtb4nCdGYsNz4cpwW8Sd
X-Google-Smtp-Source: AGHT+IHUffLjoskzvn5XhpFGAg3eC/HnwZ1yo8o70Ei5ii7HGYPJKnBVSai/N6VkTI06vnFUxveXFg==
X-Received: by 2002:a05:6870:3d8b:b0:2e8:7471:6350 with SMTP id 586e51a60fabf-30cd0db0283mr1403455fac.1.1755161780182;
        Thu, 14 Aug 2025 01:56:20 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZcZN3eS51KKVmXteiL9I7vOz/rflPomeUsTLnV0kTVGFw==
Received: by 2002:a05:6871:840a:b0:30b:8494:7c57 with SMTP id
 586e51a60fabf-30ccebf90f1ls234059fac.2.-pod-prod-09-us; Thu, 14 Aug 2025
 01:56:19 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVs8W/U0cb5Kk++H16+CfBaABwxIUuo4z9GTp7sH0MZ39oMy129EHXNCqtBQHVLBZAqVnXhxBLKnE0=@googlegroups.com
X-Received: by 2002:a05:6830:2a16:b0:73e:9293:556e with SMTP id 46e09a7af769-74382b3e1d8mr1046930a34.6.1755161779365;
        Thu, 14 Aug 2025 01:56:19 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1755161779; cv=none;
        d=google.com; s=arc-20240605;
        b=LWR9FRxCXnErHo2anIj5kzGBCiPsgZWTZk07FzwUL9tZPbUKMutyTrbJ4TD3s1aK+Q
         CcjYUYiTA4r27YrBkLIz7Zh60rEE5hn9sJakn23hvb+aYiWoc+S7ApoGUHHpDwp351c1
         a6bK+2biseufNdxBwtUSvjCrfUJzhV1mrocLrLaUtjwhqVLt0uCstiBnQLNost3qotb6
         3DZNXOgeHi+IplGxhh+eN9cTmUqYZK7B6pjJFwetzzLAAKsnbgCub2s4/m1vJagsKiPW
         A4OZ9Levo8RLAhfPWbOp5w2+THKj4zvmTevMYpdhcyHQC/ui37gO/yXOkLwsuO+bMbh9
         ALoQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-transfer-encoding:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=e46B2FI/PagtxjUFemCdMQXhTSnu4yC2Ildyjyftxdo=;
        fh=gOqAOsSLdoPOBJo0QozQvoXYivyuMTi1+Jbh8fKO3S4=;
        b=Xe5Smt/KCXX64svVhKxogytifPThjsouWm0zmHgxhLnfNwYlUR+aeoLYL3LsUyuDDn
         dYaEL1LFUzV7LrFXN2PdTE32fNJa4P0uK4aDWudxFUasb1q+ZjQWCBbZyeXPiFTw9LmG
         hun669QzqTh2uqbzrjBsQat7gD5puRF0FhFhWRRu/dHzhEXt45tcXQ6hOmNp29sxGZUR
         Ot5rk1OPN3i2amX2N1+EVwmcVeFpApv/VJf4SMwV7ThWf5r1QPP3GkMnGUigMHEixye7
         FhQnSYX+C7xXdash6pxvCMxVC5espO/ng6GLv+2IaLg/tGNDO+FHeShBZD4RDHz4lIOw
         ZRDA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=TIGQNDNh;
       spf=pass (google.com: domain of bhe@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=bhe@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.133.124])
        by gmr-mx.google.com with ESMTPS id 46e09a7af769-7436f87ba53si231002a34.2.2025.08.14.01.56.18
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 14 Aug 2025 01:56:19 -0700 (PDT)
Received-SPF: pass (google.com: domain of bhe@redhat.com designates 170.10.133.124 as permitted sender) client-ip=170.10.133.124;
Received: from mx-prod-mc-03.mail-002.prod.us-west-2.aws.redhat.com
 (ec2-54-186-198-63.us-west-2.compute.amazonaws.com [54.186.198.63]) by
 relay.mimecast.com with ESMTP with STARTTLS (version=TLSv1.3,
 cipher=TLS_AES_256_GCM_SHA384) id us-mta-422-3SOjFLgDMcqA9Xa_jao8Yg-1; Thu,
 14 Aug 2025 04:56:13 -0400
X-MC-Unique: 3SOjFLgDMcqA9Xa_jao8Yg-1
X-Mimecast-MFC-AGG-ID: 3SOjFLgDMcqA9Xa_jao8Yg_1755161771
Received: from mx-prod-int-08.mail-002.prod.us-west-2.aws.redhat.com (mx-prod-int-08.mail-002.prod.us-west-2.aws.redhat.com [10.30.177.111])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits) server-digest SHA256)
	(No client certificate requested)
	by mx-prod-mc-03.mail-002.prod.us-west-2.aws.redhat.com (Postfix) with ESMTPS id EEB141956060;
	Thu, 14 Aug 2025 08:56:10 +0000 (UTC)
Received: from localhost (unknown [10.72.112.89])
	by mx-prod-int-08.mail-002.prod.us-west-2.aws.redhat.com (Postfix) with ESMTPS id B73811800446;
	Thu, 14 Aug 2025 08:56:08 +0000 (UTC)
Date: Thu, 14 Aug 2025 16:56:04 +0800
From: "'Baoquan He' via kasan-dev" <kasan-dev@googlegroups.com>
To: Andrey Konovalov <andreyknvl@gmail.com>
Cc: linux-mm@kvack.org, ryabinin.a.a@gmail.com, glider@google.com,
	dvyukov@google.com, vincenzo.frascino@arm.com,
	akpm@linux-foundation.org, kasan-dev@googlegroups.com,
	linux-kernel@vger.kernel.org, kexec@lists.infradead.org,
	sj@kernel.org, lorenzo.stoakes@oracle.com, elver@google.com,
	snovitoll@gmail.com
Subject: Re: [PATCH v2 00/12] mm/kasan: make kasan=on|off work for all three
 modes
Message-ID: <aJ2kpEVB4Anyyo/K@MiWiFi-R3L-srv>
References: <20250812124941.69508-1-bhe@redhat.com>
 <CA+fCnZcAa62uXqnUwxFmDYh1xPqKBOQqOT55kU8iY_pgQg2+NA@mail.gmail.com>
 <CA+fCnZdKy-AQr+L3w=gfaw9EnFvKd0Gz4LtAZciYDP_SiWrL2A@mail.gmail.com>
 <aJxzehJYKez5Q1v2@MiWiFi-R3L-srv>
 <CA+fCnZfv9sbHuRVy8G9QdbKaaeO-Vguf7b2Atc5WXEs+uJx0YQ@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <CA+fCnZfv9sbHuRVy8G9QdbKaaeO-Vguf7b2Atc5WXEs+uJx0YQ@mail.gmail.com>
X-Scanned-By: MIMEDefang 3.4.1 on 10.30.177.111
X-Original-Sender: bhe@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=TIGQNDNh;
       spf=pass (google.com: domain of bhe@redhat.com designates
 170.10.133.124 as permitted sender) smtp.mailfrom=bhe@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
X-Original-From: Baoquan He <bhe@redhat.com>
Reply-To: Baoquan He <bhe@redhat.com>
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

On 08/14/25 at 07:23am, Andrey Konovalov wrote:
> On Wed, Aug 13, 2025 at 1:14=E2=80=AFPM 'Baoquan He' via kasan-dev
> <kasan-dev@googlegroups.com> wrote:
> >
> > > I'm not familiar with the internals of kdump, but would it be
> > > possible/reasonable to teach kdump to ignore the KASAN shadow region?
> >
> > Yes, we can teach kdump to do that. Then people may hate those conditio=
nal
> > check "if (is_kdump_kernel())" being added in kasan code. E.g even
> > though we skip kasan_init(), we still need to check is_kdump_kernel()
> > in kasan_populate_vmalloc(), right?
> >
> > Combined with the existing kasan_arch_is_ready(), it will make kasan co=
de
> > ugly. I planned to add kasan_enabled() via static key
> > kasan_flag_enabled, then it can also easily remove kasan_arch_is_ready(=
)
> > cleanly.
>=20
> What I had in mind was something different: into the kdump code, we
> add a check whether the region of memory it's trying to dump is the
> KASAN shadow, and make kdump not to dump this region.

Ah, I got what you mean. We probably are saying different things.

In order to record memory content of a corrupted kernel, we need reserve
a memory region during bootup of a normal kernel (usually called 1st
kernel) via kernel parameter crashkernel=3DnMB in advance. Then load
kernel into the crashkernel memory region, that means the region is not
usable for 1st kernel. When 1st kernel collapsed, we stop the 1st kernel
cpu/irq and warmly switch to the loaded kernel in the crashkernel memory
region (usually called kdump kernel). In kdump kernel, it boots up and
enable necessary features to read out the 1st kernel's memory content,
we usually use user space tool like makeudmpfile to filter out unwanted
memory content.

So this patchset intends to disable KASAN to decrease the crashkernel
meomry value because crashkernel is not usable for 1st kernel. As for
shadow memory of 1st kernel, we need recognize it and filter it away
in makedumpfile.=20

>=20
> Would this work? Would this help with the issue you have?
>=20
> (I assume the problem is with the virtual region that is the shadow
> memory, as kdump would dump all RAM either way? If not, please clarify
> what how does the "heavy burden" that the shadow memory causes
> manifests.)
>=20
> Thank you!
>=20

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/a=
J2kpEVB4Anyyo/K%40MiWiFi-R3L-srv.
