Return-Path: <kasan-dev+bncBDW2JDUY5AORBEVZQ3BQMGQEQL7VI3Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13b.google.com (mail-lf1-x13b.google.com [IPv6:2a00:1450:4864:20::13b])
	by mail.lfdr.de (Postfix) with ESMTPS id E59A5AED034
	for <lists+kasan-dev@lfdr.de>; Sun, 29 Jun 2025 22:05:42 +0200 (CEST)
Received: by mail-lf1-x13b.google.com with SMTP id 2adb3069b0e04-553ea44a706sf992046e87.0
        for <lists+kasan-dev@lfdr.de>; Sun, 29 Jun 2025 13:05:42 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1751227540; cv=pass;
        d=google.com; s=arc-20240605;
        b=DYbhb1Bi6QV++wazUo7QR/w6iIWOIBMPtMSuu4b5heK3vpO9Czr9Bvvum/5f5R5ZHD
         Uqjnfq/IScMlDKRjZum65NChhEMp9gkIcO11yWpWvo+lOTr3JBKiZwdpo4Q2QVcgoqpV
         L+PyGx/qPArwoILrHwgtHhTbOHcYN4ECaAKltGVaNnw/UdSzpw7Bl/+K1wRJv40TVauZ
         v+CUqW44vHz0Qh32b1eQoM7N9T2ORvFFZrJE/xIAWwppBoovA77BUAR3cjTmNJdcfEWI
         zuTaRQquTw+gQ3DqK25tTx/9Dc9g5bkYGO/AOVvr2EbZxB6UJwqKOWT7MNzM//Y4KaI4
         BoKg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=xDkHXCrfHT25sjvUR98YHzTK7a1T+X57NguSfX0PnIU=;
        fh=ChwOMYtYkwTiv/ieawLo+FoYs27M3J6e8UcEcWf1PjY=;
        b=enHjlsCWpZJhIyAq7tGODT4u6v5HsO2itZEUujLoLNodlaXJKuyps0mhj2CkzWUW0K
         3gXr/5sNAS7ArnLuNJfV5uiWfWhjY38Xj3XCQ2tkB2oevXSxKEetYLShS2tGt+lpLlHK
         UUcZlcIyF30nkzOW5HJfmB/bB91d0GgVqANkeAf0nxav8NNpUWT+hUWgnOIjMfWNxXDo
         Pd3tSynmsHycAhM+4B78qGxZDLzNaZ0KCAjQEvvGQHXJeU7K4NASvG8gFQyRFfo7ghQ/
         hbwUfJqUjG6zxukW1tkh+n/puelUKt/mgYFVmiGiF54VcDm0RlSXhqPhoC++vMBc8qie
         Xs4A==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b="Rt//IllU";
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::42c as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1751227540; x=1751832340; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=xDkHXCrfHT25sjvUR98YHzTK7a1T+X57NguSfX0PnIU=;
        b=o//3ruAnzcVgaEfX3t9kT1/XvarULG7yNIICK9GHQuY+cRQC3ZeZFTUZk87I1boQzH
         CzcwnJxEG6OZbVyAyONBWtblB1N+519X8KTzgfk7OPwV+7yIx90rA34DdkP6ke4n4RI1
         fee2EN/SkuxW0O2VLfRyJYAu1hV4RQwukYOlIb5QPjuTzXciTzlH/FPzdSZuq/61dnNk
         p0UYOQGVUihs2LkHfJy2+1Gd9yvVOjaT8BXfSuvcOweuyjGXXmRtVSrcNGX4CyI2MRqT
         A32wsjdP3+5QeskVuB+8xRdxm5vKSackNdHl1LK88PJQA1J8iGRuMwwnTbJUIopwRB0C
         FGRA==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1751227540; x=1751832340; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=xDkHXCrfHT25sjvUR98YHzTK7a1T+X57NguSfX0PnIU=;
        b=YDcOj0r82vs8+rFglfkbjSyV/9cXd+ZWskjl2on/ui0z4PaFtxz7ltmDxIQbFCYiuK
         s79v9Y3kT2uNPYn0gx9IQiPQ+ljhmV4g67uZ54fAbb2/gyxmbQsT6o37w3T91Es7FLYH
         tW7T7bJn9XYo7l5673Wv+tBBo2LstX7a0DPTPq1JN0WUpRX7+46C80A1M2V799PEqGTZ
         YDuafvAO0OcVL36UIycPX9ySDuHTyKq+4Y0NLxCQeAw6UUIOsec5xgh0yQj8VKa5rkWM
         hmSUfOtXnDQRDnbjqAZoZz9Ss8MqTs/+ud/aYwhPbX0JeeTquMQSWEla0aDyQsv9cRh1
         +Qnw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1751227540; x=1751832340;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=xDkHXCrfHT25sjvUR98YHzTK7a1T+X57NguSfX0PnIU=;
        b=b8eoAmpgHD8sQmL6+W8+KLV/ZyGtftHaKPLVH10V91Fui96iePKY4Iea3+FlSFACH6
         KzFUcU3LoBMpr5OMuO0PAmNonj3wOFMZZXSgfA6Wi1LVmlaTYecoGDiIan9dNKS9Rg/R
         GQjiGqDTSzGA7TmAoh7FIOMK81S3i71z+WByeanrr9cYD1EH4/+Bi0kuEFpzNFkKPjp1
         j9yjyeP5UC042DhYN8E4bOMSqGOg9mRYyVUrRnNGxd8xF6wFelux6s72AMgc6p6/4aXc
         gySZXjODxV2bseJ6V0TAhXPCsgWljC4fqf4D05ZCSVX2ddy7pg0TnI+IOVD/zilwQ94/
         4EkQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXYByOkNAJLKcNhJSYsUqBp9p6Q/d4tMIiaKmdRVHTFjN/L1pGtoLzFj9Nxr1ilg3mddAKg8g==@lfdr.de
X-Gm-Message-State: AOJu0YyQauYY5XUX4qHutAmRIk0ySTxEXjHVWJaOSaTajUpjis4cqn6M
	XFPbLU0IP8ijKUbxMu90uTNRd3I9XaN7vXhFXS2eepy8/gRDgvZzarYx
X-Google-Smtp-Source: AGHT+IFbWXUz7sBpaurUEBHOBmnAbX27h0LDrXtFROjcCaIYITvoimRzE60UhcK5/NSDoxRzEkmOlQ==
X-Received: by 2002:a05:6512:110d:b0:553:5d00:be86 with SMTP id 2adb3069b0e04-5550b9e9ca6mr3668809e87.41.1751227539656;
        Sun, 29 Jun 2025 13:05:39 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZcW6b+H8g5BT45DcVm3WeNRKR2Fe4Dt2PlnfEgycle2lg==
Received: by 2002:a05:651c:4190:b0:32a:8058:e2e7 with SMTP id
 38308e7fff4ca-32cd03948afls8034961fa.1.-pod-prod-05-eu; Sun, 29 Jun 2025
 13:05:34 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCX/SQi+0UF19zo66e6Jh4KBhByyVklDgnxnxrxJ5f5R3ODPXhIO5HU8TDz+RRxufSqGVcTv+BtsONg=@googlegroups.com
X-Received: by 2002:a05:651c:1606:b0:32c:abf4:d486 with SMTP id 38308e7fff4ca-32cdc46419emr31428831fa.14.1751227534474;
        Sun, 29 Jun 2025 13:05:34 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1751227534; cv=none;
        d=google.com; s=arc-20240605;
        b=YSEN3+ABp0pkKYR3ovc5fVhqJQJm2Rwwjw3IMxie0sYBwFWt8qSBrRNlarDAiUuS7C
         bD2KpIOo9vTUlTkCLmIGJTToBTQtEWwr/qs4nx6OCiINz9OR6l6FjhpPotvyS+VLV4lV
         BD4FaBpWaLTXYxEm9dO+o2/ylaPWc43xK+S9DcEllExjUqIOXz/LrQ6gBhU3vLOhqChF
         lkU/pz9OXciqMIotDdHEMVUToDFEZ6PyJtI/fXhV3brBi5/YKTirVMemRVBiuO5ZfIOU
         y/ee7rv1m+RNd8cbNUKXcpdjG35oxNz3NL60oVXQ09xhkeQeyDu1tgN95BFeRxDdFI8P
         gS/Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=qpjVZvBcIo5G28UGMNZaBkJZF6ITVDpFyOxvjBVjrQo=;
        fh=7pOAh46tQJdvQ01lmlfm4OjDZ5WlGCpmFrQrPd/tsg4=;
        b=HQWiOBhYNnOzlHqjp6wRdUzWdq4DhlDmSwBur4rT5MEUhoNm5UpoWakXv/TOazyRIa
         k4FPHwarlO6CfRFP3SnmrXb/OuzE+vdDHFqJA1DoJXLr5FUi9zFueIfuZq1kZgmTlPlt
         cvVrTLKSJC7sprsHyGilYju1XeNApsM49wgkCZ83M4/w1YrW+LcQ5CUR1orsYjUv2LRo
         tbsDXvkjqyGvKlvhU9kkkNFGTYAHf5opcJjr3tli178A9suP5gCC+DvuQJWGO69cdMGq
         SEpgVvKU3ftTkdT/zV89fSI9i3snBwZWrdLG3YTurS5ZCxu7Wxf0XQImlDuZRY0Q+dzr
         T1Ww==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b="Rt//IllU";
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::42c as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wr1-x42c.google.com (mail-wr1-x42c.google.com. [2a00:1450:4864:20::42c])
        by gmr-mx.google.com with ESMTPS id 38308e7fff4ca-32cd2e927d8si4225381fa.4.2025.06.29.13.05.34
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sun, 29 Jun 2025 13:05:34 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::42c as permitted sender) client-ip=2a00:1450:4864:20::42c;
Received: by mail-wr1-x42c.google.com with SMTP id ffacd0b85a97d-3a52874d593so1198320f8f.0
        for <kasan-dev@googlegroups.com>; Sun, 29 Jun 2025 13:05:34 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCWOgOA/m+4gsWKOqeVQARuQ3VWecivA+TkZ3AeA8imTaO0ATNwVAcD+JfuoET1iG+6CA1UlPLpUXak=@googlegroups.com
X-Gm-Gg: ASbGncssycBgBlKB3srQ9B9ge9rQxtydbTum0/oMJSIx3ZsHrlEfVLWIzSN8TgrCO8U
	7u78Y5K3RdJVjB9IiOwV+voNxLeApQtNUMLFqt0RNZxSDAYT/nOt+r7IL4mo/Or942Ir8Q4kj2r
	rzLIKWVHfi9vzF5xQwpPYDG+VRdd+Sseb2sGIIa2xBVMVIRWS5fvzIy7E=
X-Received: by 2002:a5d:59c7:0:b0:3a4:fc3f:ed28 with SMTP id
 ffacd0b85a97d-3a8fee64fafmr10710844f8f.29.1751227533501; Sun, 29 Jun 2025
 13:05:33 -0700 (PDT)
MIME-Version: 1.0
References: <20250626153147.145312-1-snovitoll@gmail.com> <CA+fCnZfAtKWx=+to=XQBREhou=Snb0Yms4D8GNGaxE+BQUYm4A@mail.gmail.com>
 <CACzwLxgsVkn98VDPpmm7pKcbvu87UBwPgYJmLfKixu4-x+yjSA@mail.gmail.com>
In-Reply-To: <CACzwLxgsVkn98VDPpmm7pKcbvu87UBwPgYJmLfKixu4-x+yjSA@mail.gmail.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Sun, 29 Jun 2025 22:05:22 +0200
X-Gm-Features: Ac12FXwSsH6fvJE1vEp59zDWu481tFenq-ukDXNa3gyvAGzFlMqgNHF8VfcuM6Y
Message-ID: <CA+fCnZcGyTECP15VMSPh+duLmxNe=ApHfOnbAY3NqtFHZvceZw@mail.gmail.com>
Subject: Re: [PATCH v2 00/11] kasan: unify kasan_arch_is_ready with kasan_enabled
To: Sabyrzhan Tasbolatov <snovitoll@gmail.com>
Cc: ryabinin.a.a@gmail.com, glider@google.com, dvyukov@google.com, 
	vincenzo.frascino@arm.com, linux@armlinux.org.uk, catalin.marinas@arm.com, 
	will@kernel.org, chenhuacai@kernel.org, kernel@xen0n.name, 
	maddy@linux.ibm.com, mpe@ellerman.id.au, npiggin@gmail.com, 
	christophe.leroy@csgroup.eu, paul.walmsley@sifive.com, palmer@dabbelt.com, 
	aou@eecs.berkeley.edu, alex@ghiti.fr, hca@linux.ibm.com, gor@linux.ibm.com, 
	agordeev@linux.ibm.com, borntraeger@linux.ibm.com, svens@linux.ibm.com, 
	richard@nod.at, anton.ivanov@cambridgegreys.com, johannes@sipsolutions.net, 
	dave.hansen@linux.intel.com, luto@kernel.org, peterz@infradead.org, 
	tglx@linutronix.de, mingo@redhat.com, bp@alien8.de, x86@kernel.org, 
	hpa@zytor.com, chris@zankel.net, jcmvbkbc@gmail.com, 
	akpm@linux-foundation.org, nathan@kernel.org, nick.desaulniers+lkml@gmail.com, 
	morbo@google.com, justinstitt@google.com, arnd@arndb.de, rppt@kernel.org, 
	geert@linux-m68k.org, mcgrof@kernel.org, guoweikang.kernel@gmail.com, 
	tiwei.btw@antgroup.com, kevin.brodsky@arm.com, benjamin.berg@intel.com, 
	kasan-dev@googlegroups.com, linux-arm-kernel@lists.infradead.org, 
	linux-kernel@vger.kernel.org, loongarch@lists.linux.dev, 
	linuxppc-dev@lists.ozlabs.org, linux-riscv@lists.infradead.org, 
	linux-s390@vger.kernel.org, linux-um@lists.infradead.org, linux-mm@kvack.org, 
	llvm@lists.linux.dev
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b="Rt//IllU";       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::42c
 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;       dara=pass header.i=@googlegroups.com
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

On Sat, Jun 28, 2025 at 3:25=E2=80=AFPM Sabyrzhan Tasbolatov
<snovitoll@gmail.com> wrote:
>
> On Sat, Jun 28, 2025 at 3:57=E2=80=AFPM Andrey Konovalov <andreyknvl@gmai=
l.com> wrote:
> >
> > On Thu, Jun 26, 2025 at 5:32=E2=80=AFPM Sabyrzhan Tasbolatov
> > <snovitoll@gmail.com> wrote:
> > >
> > > This patch series unifies the kasan_arch_is_ready() and kasan_enabled=
()
> > > interfaces by extending the existing kasan_enabled() infrastructure t=
o
> > > work consistently across all KASAN modes (Generic, SW_TAGS, HW_TAGS).
> > >
> > > Currently, kasan_enabled() only works for HW_TAGS mode using a static=
 key,
> > > while other modes either return IS_ENABLED(CONFIG_KASAN) (compile-tim=
e
> > > constant) or rely on architecture-specific kasan_arch_is_ready()
> > > implementations with custom static keys and global variables.
> > >
> > > This leads to:
> > > - Code duplication across architectures
> > > - Inconsistent runtime behavior between KASAN modes
> > > - Architecture-specific readiness tracking
> > >
> > > After this series:
> > > - All KASAN modes use the same kasan_flag_enabled static key
> > > - Consistent runtime enable/disable behavior across modes
> > > - Simplified architecture code with unified kasan_init_generic() call=
s
> > > - Elimination of arch specific kasan_arch_is_ready() implementations
> > > - Unified vmalloc integration using kasan_enabled() checks
> > >
> > > This addresses the bugzilla issue [1] about making
> > > kasan_flag_enabled and kasan_enabled() work for Generic mode,
> > > and extends it to provide true unification across all modes.
> > >
> > > [1] https://bugzilla.kernel.org/show_bug.cgi?id=3D217049
> >
> > Hi Sabyrzhan,
> >
> > Thank you for working on this!
> >
> > One aspect that is missing from the patches is moving the
> > kasan_arch_is_ready() calls into the include/linux/kasan.h (this is
> > not explicitly mentioned in the issue, but this is what the "adding
> > __wrappers" part is about).
> >
> > Another thing that needs careful consideration is whether it's
> > possible to combine kasan_arch_is_ready() and kasan_enabled() into the
> > same check logically at all. There's one issue mentioned in [1]:
>
> Hello,
> I've removed kasan_arch_is_ready() at all in this series:
> [PATCH v2 11/11] kasan: replace kasan_arch_is_ready with kasan_enabled
>
> Is it not what's expected by unification?

I guess the issue description diverged a bit from what needs to be
done, sorry about that.

The core 2 things I wanted to address with the unification are:

1. Avoid spraying kasan_arch_is_ready() throughout the KASAN
implementation and move these checks into include/linux/kasan.h (and
add __wrappers when required).

2. Avoid architectures redefining the same kasan_enabled global
variable/static key.

Initially, I thought that s/kasan_arch_is_ready/kasan_enabled + simply
moving the calls into affected include/linux/kasan.h functions would
be enough. But then, based on [1], turns out it's not that simple.

So now, I think we likely still need two separate checks/flags:
kasan_enabled() that controls whether KASAN is enabled at all and
kasan_arch_is_ready() that gets turned on by kasan_init() when shadow
is initialized (should we rename it to kasan_shadow_initialized()?).
But then we can still move kasan_arch_is_ready() into
include/linux/kasan.h and use the proper combination of checks for
each affected function before calling __wrappers. And we can still
remove the duplicated flags/keys code from the arch code.

[1] https://lore.kernel.org/linux-mm/CA+fCnZf7JqTH46C7oG2Wk9NnLU7hgiVDEK0EA=
8RAtyr-KgkHdg@mail.gmail.com/

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
A%2BfCnZcGyTECP15VMSPh%2BduLmxNe%3DApHfOnbAY3NqtFHZvceZw%40mail.gmail.com.
