Return-Path: <kasan-dev+bncBCCMH5WKTMGRBWP3ZPEAMGQEZNDLXGA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63a.google.com (mail-pl1-x63a.google.com [IPv6:2607:f8b0:4864:20::63a])
	by mail.lfdr.de (Postfix) with ESMTPS id 40FDCC4C8DD
	for <lists+kasan-dev@lfdr.de>; Tue, 11 Nov 2025 10:11:55 +0100 (CET)
Received: by mail-pl1-x63a.google.com with SMTP id d9443c01a7336-297dfae179bsf87710445ad.1
        for <lists+kasan-dev@lfdr.de>; Tue, 11 Nov 2025 01:11:55 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1762852313; cv=pass;
        d=google.com; s=arc-20240605;
        b=PIDOKkbkHTgFW34YhZzn9MbMnUJjrm8LrQ2mDV5CUCNFnqpNpviZ/VgNuI0a2qRus9
         KyoT/EWIcin16rspmDOJRe7ei+B94XIIfgAuEJqlmMFf+kOOI5V0LMei3JDyqr9uXhqg
         i3dRuvI9fySJi6BotITugVi3HitcFMoW63wPLUrVF2+K8TGw2rQ1GzG0TLVutwaPFzRc
         hei2KAFrID/pUEr1rtP/efg9gEzNYRoS1cPNrs3saD2UbC4qMwFJnkGv5h+58sGN5qFu
         tIQQdiV6wq750rcH6gGGFKcXPtWUhsDaJaDp2UA/QmssoFZczg86rtu2w0vtSsAw1W1y
         GhLQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=SxVKUL8oOhsG2Fkcmz1AM4HQczi8MwJIQvBYIh5wXYE=;
        fh=9elu9oBKDnL40sz6HLEuMz1G4aW8i49yi1W4H9OtKt0=;
        b=NByiN2Y1kUgUbEYxqr01eQ96YWc7t8CFJ4bx/1sdM0rCPUV8AZFcvOpsTovSQA2mcS
         Maa8rcBTE9M5kS6O9Ylvjz5SQMYzFPKKFVbqLDIHPQ/dj2/34vFnrA5HpslS6rub2EN0
         nJsnWTwjVlmIcIqYYcvQ7W7vwXvyj+NgRPbHuc1mktO8t08r9H0e8LnVCEJ4uyoFoACC
         nGJJ3LOncNA2GrRek+2OsGC/bgfzULgNbIoMNq4Z2OS0Jj/yK3ONl0iTXiBUDy6dSJ9D
         Hfxd1yf69hiPsaYf9GUtKmLSr/Ulu9kS800AqR4UHx/3PTEVIdbK2NVKMnecsJJxokz4
         C9TQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=uY+NGm8A;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f32 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1762852313; x=1763457113; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=SxVKUL8oOhsG2Fkcmz1AM4HQczi8MwJIQvBYIh5wXYE=;
        b=TZhXF+k1RP9FiNif9Kr/qiWEtNBcXkUk+1H/hqsXGfpEFaiR/oJkRC+GQGzkd8kAtN
         Qqb10BcJPjemWyHJKJn7N5WPxwqFF99hI9WMwYhBlMi6h/u/shkPsD4Hd99YdhXZ4Pgo
         XpRfjz8SfEALtDQdZ7CCNu193gyVyndNBj53UshfonzTH5984rVCHcftg8HaWIjSpWVQ
         WI2ZUQ+cuOryjLH0vVofS6vdACINSdg0ijlA3cw/0NDbkjyFmIAU5oN7Pr5taWF5QMWS
         ZnT4Fpn1ndvtEnL2n0yLQvBtgw1T6aLmlO3r2D597y+n70qFUKLUCN+r7iQJLQIEsL0s
         OZdw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1762852313; x=1763457113;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-gm-gg:x-beenthere
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=SxVKUL8oOhsG2Fkcmz1AM4HQczi8MwJIQvBYIh5wXYE=;
        b=OXhqRj3gZgaHATbOGBgyxS8E/dD496r5lARqCr+GvADCgXBXPzytBvjkPQdxXgxanm
         q9KY1Z7GjUFr8d3awtLMiqp2WsckmoFefa8JrE9LDD/bY8xCnBjayUz9A9IfFCE/UP/J
         Db/eE9oi+qFLm4sFv1ABGfyluacBXU6ACDLtNt0scqSypFYt1H3NYNs/0qVElHgVXESa
         RIYTykDagMfK1tX4aDEIl7PuBNRmwSZYb424Ph6EQ8Kmc20arS8BmS2egwRRPPz51CLY
         cyoumqr++CmbxNTj/zhB1ub8TJXjKbRsYUgm5Zhl+HNs7BDn+ghafnlCPvw05HzDnHIo
         NFnQ==
X-Forwarded-Encrypted: i=2; AJvYcCVML8mxfzmVtziSkeIkQ12OAEeINlCm6hrEIcmKd5HSRvVh0r/186ntEnX38rUSLd9Y2Acvvg==@lfdr.de
X-Gm-Message-State: AOJu0YxAHVsplb+vImy6x35ysRxYE2hzHrfOSMyAAQh17K2Gg9QLec9i
	ClM3gUp2GJKjIryvtX9dgJKZpVxTwOlrSDIG82AVixTVNcu6afeFHaDv
X-Google-Smtp-Source: AGHT+IEPNw7Q3IBrk7m+5U+XudXld7VbphoXDYjA7DBgctd878eUrpNzXm8pguTRTTmAUk0ecd25ww==
X-Received: by 2002:a17:903:13c6:b0:298:29e0:5f32 with SMTP id d9443c01a7336-29829e06167mr76303345ad.15.1762852313509;
        Tue, 11 Nov 2025 01:11:53 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="Ae8XA+Z0xjffbIyiKbiiRpCgGEFoek/KWH6vzHfFu4unofg8Ig=="
Received: by 2002:a17:902:8c96:b0:290:8ffc:aa6c with SMTP id
 d9443c01a7336-2965243397cls48765045ad.2.-pod-prod-01-us; Tue, 11 Nov 2025
 01:11:52 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCXFiqwiPQxbZxhkpOLKcYdtxrWaQREAfyULB9ltL9hei8ZZ6Q7bQ7gg0Iublm/3bNI3zwbjwCQdu38=@googlegroups.com
X-Received: by 2002:a17:903:1c5:b0:297:df17:54cd with SMTP id d9443c01a7336-297e5641b6dmr147955275ad.27.1762852312178;
        Tue, 11 Nov 2025 01:11:52 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1762852312; cv=none;
        d=google.com; s=arc-20240605;
        b=ON7aY9bFJAieKJ4gYhHaX6r9kl1FgGLbNY+Ilsv+06wa3cOnI80S9L4SqilktFaGZW
         mO3puLR2yvVkaoI5usZ9A872lysE0A2QXdzeZbRrz3FbKdo8Va/NyDlC5rGvKVO9wIDR
         n8BQCffA6Fh/cHAglARwaxV37u9/1Hz9EweZLjcKwf66IIeYc73hb7YzYIOzJeo/ET4p
         DheZ4FVkJc33TRoeAKnrZswPVtO5vVLAFAyMB0MhB8S9BOj4wLJg94VOPNZYh2ek3TC+
         wtoHC8jZyqnCa7GRq6KxcKaUo0u1NpzZk5HqmSUEYpbCBLvld1jaV2OARLbzcrkUr7mv
         gy+A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=wMAn9oTbF3Zv6YZXMFgD9SCNTI8yFt+ADFGBD5EQzqY=;
        fh=sErzDMBAuLl/6IJKklssB8V3iL5LyBQ6z+i1olEk/Ko=;
        b=RozLTvC1V7486darEJRKOnXIzq8CIHvDOWAzziNlwvkdYVmgytvg7rJSpGJEPnq+Y/
         R/D5t+bCAMiNP0s7YpmR7pqA7/25+fCeBhNzLqrtPv+bmnuwMtPbYnL9GRikMcANv+Yy
         Us3A5AGFyhkNeS5ALPC3jv3yOja9kpR9twHeddAOCbYuCDvWkJFh8nvtb2Go4eiz+uwL
         oFF0RSDBol2Jn00Rf1qJjbS95uxO9azPwZWv2NHImPIlR6xfL+0Zuy5y5oLWC0cXPgoV
         MB36WElX7J/8SFqOfVVmAsIWSegnBzk0Epi/+OtP7oQBtVZp2V5+XuiUTOdM7PEcOg0L
         KhHQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=uY+NGm8A;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f32 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-qv1-xf32.google.com (mail-qv1-xf32.google.com. [2607:f8b0:4864:20::f32])
        by gmr-mx.google.com with ESMTPS id d9443c01a7336-297ea635912si4665705ad.4.2025.11.11.01.11.52
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 11 Nov 2025 01:11:52 -0800 (PST)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f32 as permitted sender) client-ip=2607:f8b0:4864:20::f32;
Received: by mail-qv1-xf32.google.com with SMTP id 6a1803df08f44-8823dfa84c5so31589426d6.3
        for <kasan-dev@googlegroups.com>; Tue, 11 Nov 2025 01:11:52 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCX7YDc8d/vmJNAE9VPor4Fvqmo2yJQQ3A4Pdz1mQ6cYqzSd1PRhO1Q1IEJxHu2morkpL6S2jyn3y6o=@googlegroups.com
X-Gm-Gg: ASbGnctYGe79kvjEzAefmQlx80Llael+bXXTtNSfTdexFtYKQpZr9v+hbZcMQ2uanIo
	ffPITlsRLLOCkzMShEiZlRw/3+JeAkNtmdXGQ5YxZ3mFMl1bVNK3AkhV553nCF31zLM+9IkziMY
	/MDEVGmxxhAwOUqgyvydRo3JNhKJ8XIeLRJZFezlfS+j8e+JUmVnfTmFOhrMnMzS1bbhkg/Yzzf
	Q9x4BP6xO9Qt7dWxl7qJBvBlkMezrTeK+aYyrfFsNmr4oAFY1o/T+VmfNwLAdA+4eHRlXCjieni
	dvbSGtuG5FU2QgIrxlqUTUU+tpgVBeIekryT
X-Received: by 2002:ac8:7f84:0:b0:4d3:1b4f:dda1 with SMTP id
 d75a77b69052e-4eda4ff2f1fmr126391511cf.61.1762852310737; Tue, 11 Nov 2025
 01:11:50 -0800 (PST)
MIME-Version: 1.0
References: <cover.1761763681.git.m.wieczorretman@pm.me> <f533bb094a566242ec196afbde222796c6d6c084.1761763681.git.m.wieczorretman@pm.me>
In-Reply-To: <f533bb094a566242ec196afbde222796c6d6c084.1761763681.git.m.wieczorretman@pm.me>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 11 Nov 2025 10:11:14 +0100
X-Gm-Features: AWmQ_bnrR-pK5Rc9D-XEScjrYr9MOeawukkWZRpWJ1yHRGagV2Ym8rHVDa4nqXc
Message-ID: <CAG_fn=X-FB6vVtDC8WhQzF7cNePS5AtmC4W1-YfTce+5jOc+wA@mail.gmail.com>
Subject: Re: [PATCH v6 11/18] x86/kasan: KASAN raw shadow memory PTE init
To: Maciej Wieczor-Retman <m.wieczorretman@pm.me>
Cc: xin@zytor.com, peterz@infradead.org, kaleshsingh@google.com, 
	kbingham@kernel.org, akpm@linux-foundation.org, nathan@kernel.org, 
	ryabinin.a.a@gmail.com, dave.hansen@linux.intel.com, bp@alien8.de, 
	morbo@google.com, jeremy.linton@arm.com, smostafa@google.com, kees@kernel.org, 
	baohua@kernel.org, vbabka@suse.cz, justinstitt@google.com, 
	wangkefeng.wang@huawei.com, leitao@debian.org, jan.kiszka@siemens.com, 
	fujita.tomonori@gmail.com, hpa@zytor.com, urezki@gmail.com, ubizjak@gmail.com, 
	ada.coupriediaz@arm.com, nick.desaulniers+lkml@gmail.com, ojeda@kernel.org, 
	brgerst@gmail.com, elver@google.com, pankaj.gupta@amd.com, 
	mark.rutland@arm.com, trintaeoitogc@gmail.com, jpoimboe@kernel.org, 
	thuth@redhat.com, pasha.tatashin@soleen.com, dvyukov@google.com, 
	jhubbard@nvidia.com, catalin.marinas@arm.com, yeoreum.yun@arm.com, 
	mhocko@suse.com, lorenzo.stoakes@oracle.com, samuel.holland@sifive.com, 
	vincenzo.frascino@arm.com, bigeasy@linutronix.de, surenb@google.com, 
	ardb@kernel.org, Liam.Howlett@oracle.com, nicolas.schier@linux.dev, 
	ziy@nvidia.com, kas@kernel.org, tglx@linutronix.de, mingo@redhat.com, 
	broonie@kernel.org, corbet@lwn.net, andreyknvl@gmail.com, 
	maciej.wieczor-retman@intel.com, david@redhat.com, maz@kernel.org, 
	rppt@kernel.org, will@kernel.org, luto@kernel.org, kasan-dev@googlegroups.com, 
	linux-kernel@vger.kernel.org, linux-arm-kernel@lists.infradead.org, 
	x86@kernel.org, linux-kbuild@vger.kernel.org, linux-mm@kvack.org, 
	llvm@lists.linux.dev, linux-doc@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=uY+NGm8A;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f32 as
 permitted sender) smtp.mailfrom=glider@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com;       dara=pass header.i=@googlegroups.com
X-Original-From: Alexander Potapenko <glider@google.com>
Reply-To: Alexander Potapenko <glider@google.com>
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

On Wed, Oct 29, 2025 at 9:07=E2=80=AFPM Maciej Wieczor-Retman
<m.wieczorretman@pm.me> wrote:
>
> From: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>
>
> In KASAN's generic mode the default value in shadow memory is zero.
> During initialization of shadow memory pages they are allocated and
> zeroed.
>
> In KASAN's tag-based mode the default tag for the arm64 architecture is
> 0xFE which corresponds to any memory that should not be accessed. On x86
> (where tags are 4-bit wide instead of 8-bit wide) that tag is 0xE so
> during the initializations all the bytes in shadow memory pages should
> be filled with it.
>
> Use memblock_alloc_try_nid_raw() instead of memblock_alloc_try_nid() to
> avoid zeroing out the memory so it can be set with the KASAN invalid
> tag.
>
> Signed-off-by: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>
Reviewed-by: Alexander Potapenko <glider@google.com>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
AG_fn%3DX-FB6vVtDC8WhQzF7cNePS5AtmC4W1-YfTce%2B5jOc%2BwA%40mail.gmail.com.
