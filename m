Return-Path: <kasan-dev+bncBAABBOUXSS6QMGQEIIHWGLY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63e.google.com (mail-pl1-x63e.google.com [IPv6:2607:f8b0:4864:20::63e])
	by mail.lfdr.de (Postfix) with ESMTPS id ECDC4A2B21F
	for <lists+kasan-dev@lfdr.de>; Thu,  6 Feb 2025 20:21:33 +0100 (CET)
Received: by mail-pl1-x63e.google.com with SMTP id d9443c01a7336-21f49f0bd8fsf6360165ad.2
        for <lists+kasan-dev@lfdr.de>; Thu, 06 Feb 2025 11:21:33 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1738869692; cv=pass;
        d=google.com; s=arc-20240605;
        b=eK5Ix+0fEySuQAodbgzDFkWjWTpMhZrk2KSW9Q07oF58necJjnORrS4DfycEhr8FVg
         P6ygv6kU0aJ7FpV3mpwWBeVbVe7+jte10qfDktIPPtEG4CKl4r/YQWjlgN3aJKy+0tHs
         +dKqPrunMgrHxsibH4s4iG2O7/24v6cm1+TzPvjf7tMY+5LSmMFkPT4mJ6B/wI3lGtPA
         AQgztG8t0zuvWgyET/jK2B6dvOYtJh+8AAoyuRCFzIJGl3Wu8U+4GY8g6tF4ca3t3H42
         Tw6r5GVVUEAT5TYx02bF+zo5MWGCqPS09092mFwERIwyoTiqIqKgs0+G8i88zQI6L70y
         2axA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :message-id:in-reply-to:subject:cc:to:from:date:dkim-signature;
        bh=ZPbwTXSeU0s80H4FRdPT+URQaQAg3k3QRoQfH10nq9c=;
        fh=jkVxG2c9uPvkfIoBm/ivQpiwQOL0TO6LbK/pUJuFzw0=;
        b=C1g+f25vxh4T3grLDRs0XONvDxzSCNqu21bD4+vyun5ZlF5uGiwiIN4Vi28c+bEyK6
         Zl29xDcEyB3pxg6ft3urme+Gf5AmFOxERlPTR9vHslcn8Pl1yYs4SawCigZ2yabH+wkn
         GRuTGJb/MsiKyTXLj6hPqgmP4XwZGCCzpbVb74fbr2CFkY+Tih5kQX6i7VfeE7vx9vCf
         ACuoSoJP7Lg8gvs7lmrSLaO6xEeocKidVzR1PHuaEZZO/KBLb69j+EyNBBqr9L+7OpYQ
         xNhDGrxmJGjbxMyAWzuwTJq6sZnwaEuLbr+Exh7mzEUzrEyrdeWtdFW28DCPP3UaNc7p
         ybdA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gentwo.org header.s=default header.b=FYcvTqLE;
       spf=pass (google.com: domain of cl@gentwo.org designates 62.72.0.81 as permitted sender) smtp.mailfrom=cl@gentwo.org;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=gentwo.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1738869692; x=1739474492; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:message-id:in-reply-to:subject:cc:to:from:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=ZPbwTXSeU0s80H4FRdPT+URQaQAg3k3QRoQfH10nq9c=;
        b=a+zdrvkYZw4mLAbzJ7LnCAkXO9bi3NmXZSyfo+eEY6c7iXRUujoZQyMkw3c1ya2Le/
         9Z1mYdJPeXd+qmQ3zzvErnmoAhVNv2hy63iarQR8kJ66BUKbygBX3OBJ9B577tsGNDd6
         p4OsONqJcDaBOsLDcdUbI+kjJ3t92k9PYFataMFA8xzkUk9su4eKcrBmZN3yND2ZkKoP
         u/4nOk7XtGMdhJVIoptyYlEyRJlWUAJ5/PW/HPSRE3I9slT59wVKj7YkAP8LgkrO6cWv
         9E2ufqTCaDjJH4jljoe7KIqeoLVvEhLdnUJ3u+whXb9/sl6OkP6r6aPraY+PAiD9s9iD
         H7xw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1738869692; x=1739474492;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:message-id:in-reply-to:subject:cc:to:from:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=ZPbwTXSeU0s80H4FRdPT+URQaQAg3k3QRoQfH10nq9c=;
        b=TXWvYvdIeKC5M3muCVIky9iwuBcjdtn2UE9p5FGo4wz5sY9Pqf7QlEN+OFRg8nOD/9
         6KYQpCCJ7K6Zhu/kGYM1oy0QUZBogIhTk05hLoy2bEhVcw9cV97VSFTiOWt/235NgW20
         bFY49R+RsvKyzdnGIYasMpNr2gFv9FByw7s3hcrXqndtuVUmUV7Q4SY9tAZixyP5754P
         LKuFmDh88mGGxgQ2YYSPho+Y4ypcXjtRJD/hChuUfHaWUwnrADyBD9J11LklT2a7LPIF
         yHFLF4wvKu8YkyDDIzA1tiFVXkk5hJbKvHAcgephQRDqHh43KsvLwOaktZwzEsEmqBol
         hzBg==
X-Forwarded-Encrypted: i=2; AJvYcCXgI/rGybKTGTxw4xVq1M3EvHxwkOiE3SVlqvYFFTvE2j4ZVWPWwBVu0RKi4YgmZKSYaPK9hg==@lfdr.de
X-Gm-Message-State: AOJu0YyjjGSLB38F2t6gUXWocJXp9Mts+rgOoel4ymwJvuzH2twUjZ3H
	OoIX2JciBU+oHongVKOmq7s8ndk0H7Y+tId3oS4JYBfL3bw55Wg+
X-Google-Smtp-Source: AGHT+IH4s9r4z0gry5X2yt4Q1TYJy+Y8oYTwzA4fj/vMyleUyy2+5faqlf1g0ccRtCe8s0MM7sgOTg==
X-Received: by 2002:a05:6a20:6f07:b0:1e0:d5f3:f3ed with SMTP id adf61e73a8af0-1ee03a5b25emr971139637.19.1738869690757;
        Thu, 06 Feb 2025 11:21:30 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6a00:2e22:b0:725:cc85:ab16 with SMTP id
 d2e1a72fcca58-7305d7fce5fls117123b3a.0.-pod-prod-05-us; Thu, 06 Feb 2025
 11:21:30 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCXIQ/IkBy68giyzPBVY0JZbCh2qBC19jX0Nl2tmlLaq+HzLAXF4MdvfdDwn5KsoGskXy9U8+rUFMgM=@googlegroups.com
X-Received: by 2002:a05:6a00:2d8a:b0:727:3cd0:1167 with SMTP id d2e1a72fcca58-7305d5058cbmr470265b3a.21.1738869689699;
        Thu, 06 Feb 2025 11:21:29 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1738869689; cv=none;
        d=google.com; s=arc-20240605;
        b=NdwIbV9eULc7VjoQjF2U0oGZ11xsQP4CrlJrgjvpxslE1r/A8d3M+WHwOTIYAKxZNZ
         Vudc0HGVU2lEnQBfolivBqkcn1V9C9aP6n3f7rpIPhHgrTYIxeUo/1Otbpbf9hIOu1Wf
         ZAiOuT7yrlvFw6jVJeLzodrpqvAyYyHHfiX3I0vyj/M6uCtp7Oj8lLnfli60zaOUUf72
         0HYJNY/O7Qwdq/1jZyxY7rcDnyly30pIXo4dFU7BpwzJjggJDxioSoWP6z1KINRd1Omp
         rmrduK6Z5mGg8jqslqI7A1D4731ak0Kb3nw6KEBqrGc3WJD1yp+E7c2dvcGPmD1vxkS7
         uxRw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:references:message-id:in-reply-to:subject:cc:to:from
         :date:dkim-signature;
        bh=dGDAHxU8hAf6n7MjkJU+V0L68Sj414cr9oN7pT0gJ6U=;
        fh=BlQfB3bR9jS2LVVifI+ZlK3II9S7glWXqwp06dz2WNM=;
        b=RLU/oPa3MliRui9o7DmeLXh6Kw6UK8Z8ouMT2dWkoDCol2EM/vmLW9sm3oJOJnXHqw
         gkFoXoZ625bYCU4T3dWLohendvt/+DmW8uSQx6qkzZJki2psOOb6FkjsMMxF7GSt29us
         WxWyQCa+Ct5+kDIoPtoKtDFDwE642tjFzGxqtEH9IAet6TmGT0MlBFB6eNwwhmRNOU4h
         1HsMSnUXfx1ggB2hL6xs7iTNqJzmbihrYdS3gIaxLEAr/L6kW2GAzPYtdvhp9jbrBiJR
         6Swpm5g6ZvGxOtGp36NyLjfmopQVlWPZXY0TmA5iU/FeVCFjXSFIPwnixoiN3HYajg5C
         1qrg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gentwo.org header.s=default header.b=FYcvTqLE;
       spf=pass (google.com: domain of cl@gentwo.org designates 62.72.0.81 as permitted sender) smtp.mailfrom=cl@gentwo.org;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=gentwo.org
Received: from gentwo.org (gentwo.org. [62.72.0.81])
        by gmr-mx.google.com with ESMTPS id d2e1a72fcca58-73048c290b3si97327b3a.5.2025.02.06.11.21.29
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 06 Feb 2025 11:21:29 -0800 (PST)
Received-SPF: pass (google.com: domain of cl@gentwo.org designates 62.72.0.81 as permitted sender) client-ip=62.72.0.81;
Received: by gentwo.org (Postfix, from userid 1003)
	id 257D54028B; Thu,  6 Feb 2025 11:11:16 -0800 (PST)
Received: from localhost (localhost [127.0.0.1])
	by gentwo.org (Postfix) with ESMTP id 215A9400CA;
	Thu,  6 Feb 2025 11:11:16 -0800 (PST)
Date: Thu, 6 Feb 2025 11:11:16 -0800 (PST)
From: "'Christoph Lameter (Ampere)' via kasan-dev" <kasan-dev@googlegroups.com>
To: Jessica Clarke <jrtc27@jrtc27.com>
cc: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>, luto@kernel.org, 
    xin@zytor.com, kirill.shutemov@linux.intel.com, palmer@dabbelt.com, 
    tj@kernel.org, andreyknvl@gmail.com, brgerst@gmail.com, ardb@kernel.org, 
    dave.hansen@linux.intel.com, jgross@suse.com, will@kernel.org, 
    akpm@linux-foundation.org, arnd@arndb.de, corbet@lwn.net, 
    dvyukov@google.com, richard.weiyang@gmail.com, ytcoode@gmail.com, 
    tglx@linutronix.de, hpa@zytor.com, seanjc@google.com, 
    paul.walmsley@sifive.com, aou@eecs.berkeley.edu, justinstitt@google.com, 
    jason.andryuk@amd.com, glider@google.com, ubizjak@gmail.com, 
    jannh@google.com, bhe@redhat.com, vincenzo.frascino@arm.com, 
    rafael.j.wysocki@intel.com, ndesaulniers@google.com, mingo@redhat.com, 
    catalin.marinas@arm.com, junichi.nomura@nec.com, nathan@kernel.org, 
    ryabinin.a.a@gmail.com, dennis@kernel.org, bp@alien8.de, 
    kevinloughlin@google.com, morbo@google.com, dan.j.williams@intel.com, 
    julian.stecklina@cyberus-technology.de, peterz@infradead.org, 
    kees@kernel.org, kasan-dev@googlegroups.com, x86@kernel.org, 
    linux-arm-kernel@lists.infradead.org, linux-riscv@lists.infradead.org, 
    linux-kernel@vger.kernel.org, linux-mm@kvack.org, llvm@lists.linux.dev, 
    linux-doc@vger.kernel.org
Subject: Re: [PATCH 00/15] kasan: x86: arm64: risc-v: KASAN tag-based mode
 for x86
In-Reply-To: <29A74A26-E922-4A4F-9B4A-8DB0336B99DF@jrtc27.com>
Message-ID: <94f81328-a135-b99b-7f73-43fb77bd7292@gentwo.org>
References: <cover.1738686764.git.maciej.wieczor-retman@intel.com> <8bd9c793-aac6-a330-ea8f-3bde0230a20b@gentwo.org> <F974BA79-80D8-4414-9DFD-1EEF9395143C@jrtc27.com> <72837fcd-97a8-c213-0098-c8f308c3415d@gentwo.org>
 <29A74A26-E922-4A4F-9B4A-8DB0336B99DF@jrtc27.com>
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="8323329-815475849-1738869076=:2425008"
X-Original-Sender: cl@gentwo.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gentwo.org header.s=default header.b=FYcvTqLE;       spf=pass
 (google.com: domain of cl@gentwo.org designates 62.72.0.81 as permitted
 sender) smtp.mailfrom=cl@gentwo.org;       dmarc=pass (p=REJECT sp=REJECT
 dis=NONE) header.from=gentwo.org
X-Original-From: "Christoph Lameter (Ampere)" <cl@gentwo.org>
Reply-To: "Christoph Lameter (Ampere)" <cl@gentwo.org>
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

  This message is in MIME format.  The first part should be readable text,
  while the remaining parts are likely unreadable without MIME-aware tools.

--8323329-815475849-1738869076=:2425008
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

On Thu, 6 Feb 2025, Jessica Clarke wrote:

> On 5 Feb 2025, at 18:51, Christoph Lameter (Ampere) <cl@gentwo.org> wrote=
:
> > On Ampere Processor hardware there is no penalty since the logic is bui=
ld
> > into the usual read/write paths. This is by design. There may be on oth=
er
> > platforms that cannot do this.
>
> You helpfully cut out all the explanation of where the performance
> penalty comes from. But if it=E2=80=99s as you say I can only assume your
> design chooses to stall all stores until they have actually written, in
> which case you have a performance cost compared with hardware that
> omitted MTE or optimises for non-synchronous MTE. The literature on MTE
> agrees that it is not no penalty (but can be low penalty). I don=E2=80=99=
t
> really want to have some big debate here about the ins and outs of MTE,
> it=E2=80=99s not the place for it, but I will stand up and point out that
> claiming MTE to be =E2=80=9Cno performance penalty=E2=80=9D is misreprese=
ntative of the
> truth

I cannot share details since this information has not been released to be
public yet. I hear that a whitepaper will be coming soon to explain this
feature. The AmpereOne processors have been released a couple of months
ago.

I also see that KASAN_HW_TAGS exist but this means that the tags can only
be used with CONFIG_KASAN which is a kernel configuration for debug
purposes.

What we are interested in is a *production* implementation with minimal
software overhead that will be the default on ARM64 if the appropriate
hardware is detected. That in turn will hopefully allow other software
instrumentation that is currently used to keep small objects secure and in
turn creates overhead.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/9=
4f81328-a135-b99b-7f73-43fb77bd7292%40gentwo.org.

--8323329-815475849-1738869076=:2425008--
