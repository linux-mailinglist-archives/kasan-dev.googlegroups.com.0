Return-Path: <kasan-dev+bncBDW2JDUY5AORBMP4SS6QMGQEHKBO2PY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43c.google.com (mail-wr1-x43c.google.com [IPv6:2a00:1450:4864:20::43c])
	by mail.lfdr.de (Postfix) with ESMTPS id DE61CA2B5FE
	for <lists+kasan-dev@lfdr.de>; Thu,  6 Feb 2025 23:56:51 +0100 (CET)
Received: by mail-wr1-x43c.google.com with SMTP id ffacd0b85a97d-38dbe6a1ba6sf471365f8f.0
        for <lists+kasan-dev@lfdr.de>; Thu, 06 Feb 2025 14:56:51 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1738882611; cv=pass;
        d=google.com; s=arc-20240605;
        b=Xe5ATvb6BWTWaGkZe/xGkbznsJPA113a/zj6CpA2kF6Ya6u9QoLi2gjl3VdLmtyfVH
         iC2HWb6CUl30aDV1GYwPLK0TMfh+Xfi3YAu5E5CimfhIj1PIwSqzggrqRvIt2HEo+VX/
         4uBOJHfFb8Iz6soQPaQAmAsLy5EK+m+a/EV1/mD0YtsjsVaYCsQbikmcjPxmXI1eAE3h
         UHae5UCpAKCfwSvw6fBs8RxenwM3hbLXMhNqS5TLTRzVR4iCoDHmwFRiIex7ZSwMIguQ
         VOizk37WqmXZkxtGwHi8/6RxHRZWrpFE7QHXZF/YzO/Tc9BLMMN25sNaQetSGjtpiBzr
         cKfg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=uaqUjLBjj+ESOeZhVbOnZKljLHkUC0wrz6B2lktOnCk=;
        fh=YX4kdn6+81WtfVqEgRiiUZGrX/vOVtrUla1UHS80ftE=;
        b=kTCWweS2cqT1Qow5TqTg/hlvjVoH8w9lmiXsQF2qm1UJLNV+/QCNWv5dtuedixGfnY
         uX8CqhFjAtu0IUfPIuc7qsxq2qNH+9qtJgmgcYTp/ankvbo2tJTRmKX74i/ZHnSg6mA+
         vUq8jR/D9YweKvJcEtZ60+4zs+ABiSn17tuZKbGyPNY9N50F7vFq+XV2JTVuxGKnJjm0
         6PPtLD+QR5AZlX3c81nsX5UgQ5hO6yl8V7dOShe7/qk9KMvHiFMmJtZMQtFMMfqM3kj4
         gNlUBsk1z6NnAhFmiF8paunkT1rZLReQYFcmxnGfriDb89Dr4VEHM9OE6OVgaDNHvsQa
         L2wA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=YM2hN0d4;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::42b as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1738882611; x=1739487411; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=uaqUjLBjj+ESOeZhVbOnZKljLHkUC0wrz6B2lktOnCk=;
        b=GyPF+jU+94qZbjk9p9vkUT049I+S7NvkFsex17MTZHa6z8EUDnexAKYkoDRQTOpsXN
         OGHIn3AO/vx6+dAgY4+Yuj1Vyboec5tMO83bSYTyBWWgR5F6R3JyAWNrxLOIfpKbx208
         cDl/0JelG/mwsZ80G3UitRoM8PIzZVZHn/zOzZPzf5xysFOCWu/zJARuuGT6XvCFLRz2
         GpRSB5VxAo3E8QPxGVVuspPJOkESXt8TEEXdLqnj3FvRvJUNtcdf/CNlet3AVyMf/M+/
         sABqYCK7hehdQz0osa+6oObSRXTDewVGeHjVKozzDlFuUqCbTmjlqlIXy6+FCpuzWkya
         ENNw==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1738882611; x=1739487411; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=uaqUjLBjj+ESOeZhVbOnZKljLHkUC0wrz6B2lktOnCk=;
        b=Zv/csix/4vjh9PdxoDW9bs3fR3xsAxzUTzjW2muYYom2waaq7vkyrr2xe4IMPB1qVC
         DpenE/YZ81eKj+0+22k0q342ye1L/pWY9yOCjrxBPDlMbhSf/m+gc6bECgy5nllFiF0/
         C/xKu6tKO2yrGDqulglpWxtO8nUGEHkwYWCbASBsHEjfxIz/FL9WZXQ9wExvhJAns0pl
         oQ8quy6TGDCU/F1Ts+qja2/GD1sWt1zLnPFlUgkBk6ys8Qg20SRkAS/n0OtqGV4HDkuH
         oh6lQqiULeZdbRCqd9OMoyWbCX+G4IEs4fygNH+SYRUDF0BTZ3LxouinghVktl2n7LKd
         aJyQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1738882611; x=1739487411;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=uaqUjLBjj+ESOeZhVbOnZKljLHkUC0wrz6B2lktOnCk=;
        b=dpVyEQWWgkAIJ4VbKGcfux4HosdDKs+a5QRrey2W71LJBgzc1okg8Y4/ci2Z1I2HrV
         QqnLK4Iuzam05CjFgteQB/Jw1//XjWMVJr5GyragbL35npRpM9eOrzvATefo/n424YJh
         Mk5qZfNDN/OvvJO4zZ5rT+5sctG02zvwdNQvRaUqPKGI9X8UhMsRE2jSzD7w0avyJa3C
         4w8npD2c5eTE/1QiWFD2ccUeZQoRzHzIaKJgiohkCnyKzzIzEzDL5iXXvqBYPOZSwB1S
         iLuHIcKCxVkoSwjUWNEQvyNaEd7O8Xkkg/aJ75XMWlejQTszXqa/1u/WZt88ei0rABvJ
         toMQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCU1OC27G82p9JZ9ABqkhByEEkdr2PXHJzzwg78je8cs5BXI6t+20Tw1F47UnrJ1NKwJrflx8Q==@lfdr.de
X-Gm-Message-State: AOJu0YyHA0j0OAB5ow3EeNRggb6nwFWvzfoMDlT2BEEViia4u5BU6BSx
	eYn1j6tTdBjxv3ZwImu371FltIP5W1TsY6QmJgc6jiF09Gtqc9QH
X-Google-Smtp-Source: AGHT+IH7UeO29chrK5+/R3ALcLRBqFM4bIethmZwyWdypo6zptsSz51ej5iT/yQHAhJpdOFcSOXGEw==
X-Received: by 2002:a5d:484c:0:b0:38d:c31b:61c2 with SMTP id ffacd0b85a97d-38dc912470fmr446304f8f.19.1738882609960;
        Thu, 06 Feb 2025 14:56:49 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:a419:0:b0:38d:bf64:17c3 with SMTP id ffacd0b85a97d-38dc8dd9728ls77003f8f.1.-pod-prod-06-eu;
 Thu, 06 Feb 2025 14:56:48 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCViBSA0UuW8okBuOy26ot2Sdv5m/pszdzj0lsLPrYbB11U6F59cmCOOliDqCoRKKzT5Wcr8B17JsbA=@googlegroups.com
X-Received: by 2002:a05:6000:1448:b0:385:ee40:2d88 with SMTP id ffacd0b85a97d-38dc90e39c5mr575004f8f.3.1738882607619;
        Thu, 06 Feb 2025 14:56:47 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1738882607; cv=none;
        d=google.com; s=arc-20240605;
        b=gHxrUSCPlmbxFYbuor2KCnmPi0946Im0S6zESEHhhPr+wEcX4gSeAWQMygYAlKUr2I
         cyZshLkvObkbMuZSSbfK6tleOC7vR8S2yISkZ7JApemHgLzIY2zlPvUW2n72Xi0hGnC+
         RJAujOlHOzOalih0l8g6IfMBvF1XkdyrAAvNzbkzzXFG9sT99tu5F4f+w9qOhu3CeTcS
         dxFIJC+oGkflQuAb1+xHLyG31nbwKF2Mp3byKqmikZLvhfdJxYxC+gd1Y+WUf6X8h360
         xCvi1wVmGrNF0gnloz1ErVBcE6Kxa2IfFqlpvxo0YUuh+GbEj7EPfHBy0eulBnMGQMrj
         ywaw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=oPdz+11/bNSSDH103V+kKB8X98fGo5sDYDlVXDLnzsQ=;
        fh=LBv+/U8o6jV+OAEjrE+Y1ps8u/5FOq453QQXqK2CALQ=;
        b=LgUJmE+MNm4c5aPQHoOulRsw7l1ZQ5J/Ju5X97jDGqQ3o6+LQI7H8N6rboPHS4E0YQ
         IofrZVXQlhOkh16WQz9a0TrDova+4lvdgaMCVq+0L+DjoUAA/dTjUXBnkctNLNtOjpOR
         hN2mWqvzgolBPCgt8FUrHevmhVLQpdYK8+1HcijNfpHBCHqAN+aI1fqRYTOz5eOOsp1d
         ODNWB+ycpcH+lODE638Z1jvHqKPNnv/qfJYZu/P4NcLJl7yL0J0vShcLUsMuMDTrlTyr
         egocBBpuPJJr4IvVBnKXpAvM3C3rGa3PW3/v1Wap3uEYEMIxXfMJpUKf20C8pIDcNB02
         lEbA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=YM2hN0d4;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::42b as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wr1-x42b.google.com (mail-wr1-x42b.google.com. [2a00:1450:4864:20::42b])
        by gmr-mx.google.com with ESMTPS id ffacd0b85a97d-38dbdc3d501si54142f8f.0.2025.02.06.14.56.47
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 06 Feb 2025 14:56:47 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::42b as permitted sender) client-ip=2a00:1450:4864:20::42b;
Received: by mail-wr1-x42b.google.com with SMTP id ffacd0b85a97d-38dcb33cba1so86f8f.2
        for <kasan-dev@googlegroups.com>; Thu, 06 Feb 2025 14:56:47 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCUUHB1YI+mqk2m7A6DpFvDE1lKtLxRAsw2G8lFu711hJQLW8rNjY6fgny6G202GMnJwS0Lj+buSNV4=@googlegroups.com
X-Gm-Gg: ASbGncvyMNtJK1Vn8jftRTFIIJBVN+90NXVXiI9tRQWn0jAFcxafw/YRmZipGD28NhT
	NbeEI+P4RqeSaiy4PGxMRNkSQgzxniSi1T6shXVBCjNtRB2wbEPcZkHl2cDSHLVjxdRRYdopK9H
	k=
X-Received: by 2002:a05:6000:154b:b0:38a:8ed1:c5c7 with SMTP id
 ffacd0b85a97d-38dc9491e7amr426795f8f.46.1738882602687; Thu, 06 Feb 2025
 14:56:42 -0800 (PST)
MIME-Version: 1.0
References: <cover.1738686764.git.maciej.wieczor-retman@intel.com>
 <8bd9c793-aac6-a330-ea8f-3bde0230a20b@gentwo.org> <F974BA79-80D8-4414-9DFD-1EEF9395143C@jrtc27.com>
 <72837fcd-97a8-c213-0098-c8f308c3415d@gentwo.org> <29A74A26-E922-4A4F-9B4A-8DB0336B99DF@jrtc27.com>
 <94f81328-a135-b99b-7f73-43fb77bd7292@gentwo.org>
In-Reply-To: <94f81328-a135-b99b-7f73-43fb77bd7292@gentwo.org>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Thu, 6 Feb 2025 23:56:31 +0100
X-Gm-Features: AWEUYZmoPWHhToAFkBuF21oc_INOOZFv4ej_J9A_VfxRgRnaQMcmFMInFI5cvqQ
Message-ID: <CA+fCnZfzPLiBcCLQTwkgBqP1D6Cw-gFrpKEpTHs5PYp07hYXug@mail.gmail.com>
Subject: Re: [PATCH 00/15] kasan: x86: arm64: risc-v: KASAN tag-based mode for x86
To: "Christoph Lameter (Ampere)" <cl@gentwo.org>
Cc: Jessica Clarke <jrtc27@jrtc27.com>, 
	Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>, luto@kernel.org, xin@zytor.com, 
	kirill.shutemov@linux.intel.com, palmer@dabbelt.com, tj@kernel.org, 
	brgerst@gmail.com, ardb@kernel.org, dave.hansen@linux.intel.com, 
	jgross@suse.com, will@kernel.org, akpm@linux-foundation.org, arnd@arndb.de, 
	corbet@lwn.net, dvyukov@google.com, richard.weiyang@gmail.com, 
	ytcoode@gmail.com, tglx@linutronix.de, hpa@zytor.com, seanjc@google.com, 
	paul.walmsley@sifive.com, aou@eecs.berkeley.edu, justinstitt@google.com, 
	jason.andryuk@amd.com, glider@google.com, ubizjak@gmail.com, jannh@google.com, 
	bhe@redhat.com, vincenzo.frascino@arm.com, rafael.j.wysocki@intel.com, 
	ndesaulniers@google.com, mingo@redhat.com, catalin.marinas@arm.com, 
	junichi.nomura@nec.com, nathan@kernel.org, ryabinin.a.a@gmail.com, 
	dennis@kernel.org, bp@alien8.de, kevinloughlin@google.com, morbo@google.com, 
	dan.j.williams@intel.com, julian.stecklina@cyberus-technology.de, 
	peterz@infradead.org, kees@kernel.org, kasan-dev@googlegroups.com, 
	x86@kernel.org, linux-arm-kernel@lists.infradead.org, 
	linux-riscv@lists.infradead.org, linux-kernel@vger.kernel.org, 
	linux-mm@kvack.org, llvm@lists.linux.dev, linux-doc@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=YM2hN0d4;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::42b
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

On Thu, Feb 6, 2025 at 8:21=E2=80=AFPM 'Christoph Lameter (Ampere)' via
kasan-dev <kasan-dev@googlegroups.com> wrote:
>
> I cannot share details since this information has not been released to be
> public yet. I hear that a whitepaper will be coming soon to explain this
> feature. The AmpereOne processors have been released a couple of months
> ago.
>
> I also see that KASAN_HW_TAGS exist but this means that the tags can only
> be used with CONFIG_KASAN which is a kernel configuration for debug
> purposes.
>
> What we are interested in is a *production* implementation with minimal
> software overhead that will be the default on ARM64 if the appropriate
> hardware is detected. That in turn will hopefully allow other software
> instrumentation that is currently used to keep small objects secure and i=
n
> turn creates overhead.

Is there anything specific CONFIG_KASAN + CONFIG_KASAN_HW_TAGS do that
is not good enough for a production environment?

The last time I did some perf tests (a year+ ago on Pixel 8, I
believe), the two expensive parts of CONFIG_KASAN_HW_TAGS were:

1. Collecting stack traces. Thus, this can now be disabled via
kernel.stacktrace=3Doff. And there's a tracking bug to add a
production-grade implementation [1];

2. Assigning memory tags to large allocations, specifically page_alloc
allocations with large orders  (AFAIR is was specifically assigning
the tags, not checking them). Thus, this can now be controlled via
kasan.page_alloc.sample(.order).

There's definitely room for optimization and additional config options
that cut down KASAN checks (for example, disabling tag checking of
mempool allocations; although arguably, people might want to have this
in a production environment.)

Otherwise, it's unclear to me what a new production-grade MTE
implementation would do different compared to KASAN_HW_TAGS. But if
there's something, we can just adjust KASAN_HW_TAGS instead.

[1] https://bugzilla.kernel.org/show_bug.cgi?id=3D211785

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
A%2BfCnZfzPLiBcCLQTwkgBqP1D6Cw-gFrpKEpTHs5PYp07hYXug%40mail.gmail.com.
