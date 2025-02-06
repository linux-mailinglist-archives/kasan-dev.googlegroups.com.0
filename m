Return-Path: <kasan-dev+bncBCV7JPVCWIDRBBEWSC6QMGQEGWUM5PY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33e.google.com (mail-wm1-x33e.google.com [IPv6:2a00:1450:4864:20::33e])
	by mail.lfdr.de (Postfix) with ESMTPS id A053FA29E2E
	for <lists+kasan-dev@lfdr.de>; Thu,  6 Feb 2025 02:06:14 +0100 (CET)
Received: by mail-wm1-x33e.google.com with SMTP id 5b1f17b1804b1-4361ac8b25fsf1729275e9.2
        for <lists+kasan-dev@lfdr.de>; Wed, 05 Feb 2025 17:06:14 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1738803974; cv=pass;
        d=google.com; s=arc-20240605;
        b=fEDqmPntAXUeTQ+rTgz598RQ/tJhQMg1lZpjqEnH0IpVxWIKuAoMQwIIaHbqdqQ3lP
         293NHGs5bVOtsiRV+6L9SzL2AHWh+GAAFNDi6pqzTl5BXZkg0pxuQOima6JP0i6G+c2G
         lWsmzxJQ4tUxVdd7OZqu4Um9ZzdDUHn2Kts5j6OydR3SpHzsDAh9oiseOWY4pGUABhwi
         JnuI8P5AaMI5p4bAUmmcgdTXWL96kP937ohEFD6x4G0FqyUE2pXrZbgOmakfKieyaxBi
         7dUx2SpDUeRhn+nQP44GuWgcIeEKTBd4e3S4kVwXcW0NOx+6CTNZaRjjcC4DmaJVSf3M
         wobA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:to:references:message-id
         :content-transfer-encoding:cc:date:in-reply-to:from:subject
         :mime-version:sender:dkim-signature;
        bh=6o7S4KJPdfq4cWA/5W7mlwQMegQ7IK8iwCjCG32p5EQ=;
        fh=s9kUwTKam1pIZ/G4mKhIkdo2UN2VSAuNEjEEQ/BZmc0=;
        b=Rip/pOMGdf3kUGJMC5tQZWWt6bBJGrnFJplubKT1oesw7RvPK+/C8CLXE1dw1rHXAO
         Yz5Hwd+uMzrsovhe6wal3FsMz75Yn5eKhB0FgZBXNB6HyaN6bpl6+63U3qS+BT5wI3tq
         dZTW0RgGlBxarNXH+9Lp0OQ99hbSNNBiMuO1UdCwkCVQDyOq/HAaulHFyvc6l9qlHC5R
         SNu3rV2bfzYvCGq/X/84vWOV3Pz1CLT2r1zzLZBDLC8oEnPdDsqt3NSCOzK7FRz6CtHF
         dvi20uY4LR+rJhTgK/QY7tH6SU2+6YpR+m7skDBrt6fZdD4dtn3RWUhA6p6bH9R0ckPY
         Ci3Q==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@jrtc27.com header.s=gmail.jrtc27.user header.b=b3uAKxwW;
       spf=pass (google.com: domain of jrtc27@jrtc27.com designates 2a00:1450:4864:20::335 as permitted sender) smtp.mailfrom=jrtc27@jrtc27.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1738803974; x=1739408774; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:to:references:message-id
         :content-transfer-encoding:cc:date:in-reply-to:from:subject
         :mime-version:sender:from:to:cc:subject:date:message-id:reply-to;
        bh=6o7S4KJPdfq4cWA/5W7mlwQMegQ7IK8iwCjCG32p5EQ=;
        b=hRn0p/vxvAQk+1M2KMrGWlm646Hqn4mX9HHtVi9SGfi99xUreVA+MPSUynAC7O4sxZ
         n2kH8tfWeMCD51miQQbgNtv8ITo0ybQX1hjoWTKDL5oXdbrMT2ugeC0J401rOFv0zYR6
         56xkn3FOrxee9HmsiXsAHR8Nmz4qz+a7Vb9i36V2e7RCCITbbK1Ku98Qln7U7K4txRWb
         ezVmAMicfeWvj2otqylLy7YA4PSAeyYM/xwDMLNjdtiEMO+vJQ/iTQoiNVLzHOPx8KXI
         xppbZ4cwShnnoU8NnQcVKG9Iu3Hpna+fE8v8IsTsl/QqXS9MKRAu+y5jgy5gqQQphUp7
         gGwQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1738803974; x=1739408774;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:to:references
         :message-id:content-transfer-encoding:cc:date:in-reply-to:from
         :subject:mime-version:x-beenthere:x-gm-message-state:sender:from:to
         :cc:subject:date:message-id:reply-to;
        bh=6o7S4KJPdfq4cWA/5W7mlwQMegQ7IK8iwCjCG32p5EQ=;
        b=Jze7I0rE9kta5tCMfRazjJgXx/tpytEqB7smM42bdDw8+bDr36kUtnuSSixXcOQhMX
         L761VjN3Kqow4brV/Hmd72rnPP+BpriA6LDY33AYvG8y/+vht4g25ayz7kilBUSoEEak
         evbIFAV7WkpcQGVmCOBy+sxqzEij45EisAO6WywIc75Ne+qXNYQuxkIDGvrUndDwoDEE
         zn4k0Tls19olB34Ss/12TY1qNRhyyl6fvkoff4f8b8G3N64XLGZKFwCMALzonrtE+bbc
         Rf9EGRr+YILM9USEHP+HLZil5bhmYMteo5Oczm55sDt2s7xoVJC5TLfFATEXW5r4/EcN
         BpdA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXrych0+KwVdDe8B79CUlCgCMYJLZ+ZK/Ip08VJFiWPFYMc6n9Zu4wfWlC3Gba67X8xTQUk8w==@lfdr.de
X-Gm-Message-State: AOJu0YyFexBB4Ij+ALsexB3+8t5wwBh/Paodbc9573ceKM4ar9R1NGdZ
	kDGD/C1x+GPk01QuBLoyDwiSnmnBVVjW57yHfkJq9tWJCsj6GK8k
X-Google-Smtp-Source: AGHT+IHtToe9soWQOBYL1GnQ6lnP/xn1KlyQHWxvz0KkNx2pbf9iDhRL05kJqWDMoVahZsa0JU9pOg==
X-Received: by 2002:a05:600c:3109:b0:436:1c0c:bfb6 with SMTP id 5b1f17b1804b1-4390d5a32c3mr39786415e9.27.1738803972682;
        Wed, 05 Feb 2025 17:06:12 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:b30e:0:b0:386:35de:28fc with SMTP id ffacd0b85a97d-38dbae01dddls149314f8f.1.-pod-prod-08-eu;
 Wed, 05 Feb 2025 17:06:10 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCUFhTkNt+3vMJeilBiLEz25drtWCBjB0fA5IkI2ta2lBdoD000aoGbNZtLvw7Uvnm2Y+WMdGqc3wG8=@googlegroups.com
X-Received: by 2002:a5d:64ec:0:b0:38c:1270:f966 with SMTP id ffacd0b85a97d-38db4860dedmr2922396f8f.7.1738803970534;
        Wed, 05 Feb 2025 17:06:10 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1738803970; cv=none;
        d=google.com; s=arc-20240605;
        b=Bmbon8rJldcWmW3DiARr2kYembbVQvfo8iSLnmGOojqh/DSpR7AfoLsUn8BJDg8Fjt
         44t3CIS7llimQbKmW/csQuqH069Cbc8doMSADgK0+JVH0efL1BarbCPx64sS+CtQXGeZ
         x9flfNPI0tJsii6a9QE+uL2vMrax2c18yU3hTNzeDRid4wlukbFb+5aJtu5gnCeHXGec
         uNFw/Q0lMz0YJcH+VdTncPb67ZEkl/Yws7SEEm5UI/ftQrGWZ9JgvaVB6Txm6LYrobtT
         VGolptVHiEK8Uv+7ijFndZ+gvFhV/tPldj6sLxI0h9h1PDj4y8QfVw+TUCsgvO0n1oNo
         v8lQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=to:references:message-id:content-transfer-encoding:cc:date
         :in-reply-to:from:subject:mime-version:dkim-signature;
        bh=IXC13o6D8+SRcnZ4bUuI8mYmE2RIqCqJ9wgb+sl11jc=;
        fh=ZI5pRZ6Uscw5bMK8LXK5Hp+z0If2EPvOJi83ubZEBI4=;
        b=FrjHFXT6GtCW5IUdL3iupkrtQmsu64ENZcbR9XTqQhLvyt/agEtJAE/VZP3c+FpSx0
         OrL31weTIZ0q9JX5yfOh2ajnDPJFPt+54ngKswFTpaQaiec12Sxi1oD4CwSvap+jtkzI
         tyQ7n00npzLyTi0AeNE/fK3skud9b2V6SOfZyEdh9OhCcAzinyYEtmj3rHLmVb2qZ/Jb
         Sgyv76Mpbc1GULaUCxX92d8GDd1CzjvfXTdb0Zl9NwCvwfIuFOvjRBhKLoMP/EcX5mFo
         ZRikBHvvK+GUgC24fdocr4TGWWiCBWogvCYFraHQBvQ7D1t1vgEDEWJaDbuSTlSM2QVM
         KW5A==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@jrtc27.com header.s=gmail.jrtc27.user header.b=b3uAKxwW;
       spf=pass (google.com: domain of jrtc27@jrtc27.com designates 2a00:1450:4864:20::335 as permitted sender) smtp.mailfrom=jrtc27@jrtc27.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wm1-x335.google.com (mail-wm1-x335.google.com. [2a00:1450:4864:20::335])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-4391df9261bsi26515e9.2.2025.02.05.17.06.10
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 05 Feb 2025 17:06:10 -0800 (PST)
Received-SPF: pass (google.com: domain of jrtc27@jrtc27.com designates 2a00:1450:4864:20::335 as permitted sender) client-ip=2a00:1450:4864:20::335;
Received: by mail-wm1-x335.google.com with SMTP id 5b1f17b1804b1-4362bae4d7dso2222805e9.1
        for <kasan-dev@googlegroups.com>; Wed, 05 Feb 2025 17:06:10 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCXCVxN55QKd7dC49HYGpaq6KWsB+TtHvbmucUSfOeCogTXE5UNG6JSH097aFSWk4ezP0CjRwI0eOEM=@googlegroups.com
X-Gm-Gg: ASbGncsN+u+8OYCyMoegC9f99nOewFRg5SxuPQp87mPYRtKo4N847WImQW/aDOCKAON
	fhctLrtXjJJF6ZSQNhvyEwT9Pei8As950mNd9FUnnbv3ZwNijv9LGWqdv6AJXXnIXmy6ZaVP39o
	5A2NlLJJ0E5lZ6YT/AHzClTkQU8+jN/A/tD0htvNRd8Kzc4Dnnd1o+t/9emsKug+J5vbInnVmwY
	YgNEX/KklqOu+WXvKyzsQBVUH2Brn59YsRDWCUddedYbJc1QrGOr9wy3qG7c5rFA3ITht+hyME8
	CmvdwVdidjpHSap2z6lFzXHc1UvF
X-Received: by 2002:a05:6000:1f87:b0:386:3e48:f732 with SMTP id ffacd0b85a97d-38db4873819mr4226170f8f.16.1738803969824;
        Wed, 05 Feb 2025 17:06:09 -0800 (PST)
Received: from smtpclient.apple ([131.111.5.201])
        by smtp.gmail.com with ESMTPSA id ffacd0b85a97d-38dbde1dcc7sm246954f8f.88.2025.02.05.17.06.07
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 05 Feb 2025 17:06:08 -0800 (PST)
Content-Type: text/plain; charset="UTF-8"
Mime-Version: 1.0 (Mac OS X Mail 16.0 \(3826.300.87.4.3\))
Subject: Re: [PATCH 00/15] kasan: x86: arm64: risc-v: KASAN tag-based mode for
 x86
From: Jessica Clarke <jrtc27@jrtc27.com>
In-Reply-To: <72837fcd-97a8-c213-0098-c8f308c3415d@gentwo.org>
Date: Thu, 6 Feb 2025 01:05:56 +0000
Cc: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>,
 luto@kernel.org,
 xin@zytor.com,
 kirill.shutemov@linux.intel.com,
 palmer@dabbelt.com,
 tj@kernel.org,
 andreyknvl@gmail.com,
 brgerst@gmail.com,
 ardb@kernel.org,
 dave.hansen@linux.intel.com,
 jgross@suse.com,
 will@kernel.org,
 akpm@linux-foundation.org,
 arnd@arndb.de,
 corbet@lwn.net,
 dvyukov@google.com,
 richard.weiyang@gmail.com,
 ytcoode@gmail.com,
 tglx@linutronix.de,
 hpa@zytor.com,
 seanjc@google.com,
 paul.walmsley@sifive.com,
 aou@eecs.berkeley.edu,
 justinstitt@google.com,
 jason.andryuk@amd.com,
 glider@google.com,
 ubizjak@gmail.com,
 jannh@google.com,
 bhe@redhat.com,
 vincenzo.frascino@arm.com,
 rafael.j.wysocki@intel.com,
 ndesaulniers@google.com,
 mingo@redhat.com,
 catalin.marinas@arm.com,
 junichi.nomura@nec.com,
 nathan@kernel.org,
 ryabinin.a.a@gmail.com,
 dennis@kernel.org,
 bp@alien8.de,
 kevinloughlin@google.com,
 morbo@google.com,
 dan.j.williams@intel.com,
 julian.stecklina@cyberus-technology.de,
 peterz@infradead.org,
 kees@kernel.org,
 kasan-dev@googlegroups.com,
 x86@kernel.org,
 linux-arm-kernel@lists.infradead.org,
 linux-riscv@lists.infradead.org,
 linux-kernel@vger.kernel.org,
 linux-mm@kvack.org,
 llvm@lists.linux.dev,
 linux-doc@vger.kernel.org
Content-Transfer-Encoding: quoted-printable
Message-Id: <29A74A26-E922-4A4F-9B4A-8DB0336B99DF@jrtc27.com>
References: <cover.1738686764.git.maciej.wieczor-retman@intel.com>
 <8bd9c793-aac6-a330-ea8f-3bde0230a20b@gentwo.org>
 <F974BA79-80D8-4414-9DFD-1EEF9395143C@jrtc27.com>
 <72837fcd-97a8-c213-0098-c8f308c3415d@gentwo.org>
To: "Christoph Lameter (Ampere)" <cl@gentwo.org>
X-Mailer: Apple Mail (2.3826.300.87.4.3)
X-Original-Sender: jrtc27@jrtc27.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@jrtc27.com header.s=gmail.jrtc27.user header.b=b3uAKxwW;
       spf=pass (google.com: domain of jrtc27@jrtc27.com designates
 2a00:1450:4864:20::335 as permitted sender) smtp.mailfrom=jrtc27@jrtc27.com;
       dara=pass header.i=@googlegroups.com
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

On 5 Feb 2025, at 18:51, Christoph Lameter (Ampere) <cl@gentwo.org> wrote:
>=20
> On Tue, 4 Feb 2025, Jessica Clarke wrote:
>=20
>> It=E2=80=99s not =E2=80=9Cno performance penalty=E2=80=9D, there is a co=
st to tracking the MTE
>> tags for checking. In asynchronous (or asymmetric) mode that=E2=80=99s n=
ot too
>=20
>=20
> On Ampere Processor hardware there is no penalty since the logic is build
> into the usual read/write paths. This is by design. There may be on other
> platforms that cannot do this.

You helpfully cut out all the explanation of where the performance
penalty comes from. But if it=E2=80=99s as you say I can only assume your
design chooses to stall all stores until they have actually written, in
which case you have a performance cost compared with hardware that
omitted MTE or optimises for non-synchronous MTE. The literature on MTE
agrees that it is not no penalty (but can be low penalty). I don=E2=80=99t
really want to have some big debate here about the ins and outs of MTE,
it=E2=80=99s not the place for it, but I will stand up and point out that
claiming MTE to be =E2=80=9Cno performance penalty=E2=80=9D is misrepresent=
ative of the
truth

Jess

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/2=
9A74A26-E922-4A4F-9B4A-8DB0336B99DF%40jrtc27.com.
