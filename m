Return-Path: <kasan-dev+bncBDAOJ6534YNBBOXB57BAMGQEDCBPCZI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23e.google.com (mail-lj1-x23e.google.com [IPv6:2a00:1450:4864:20::23e])
	by mail.lfdr.de (Postfix) with ESMTPS id 4D357AE8328
	for <lists+kasan-dev@lfdr.de>; Wed, 25 Jun 2025 14:51:08 +0200 (CEST)
Received: by mail-lj1-x23e.google.com with SMTP id 38308e7fff4ca-32cbc4a763esf6470831fa.3
        for <lists+kasan-dev@lfdr.de>; Wed, 25 Jun 2025 05:51:08 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1750855867; cv=pass;
        d=google.com; s=arc-20240605;
        b=hC6CWeZuIXR7tbZ7lUlsaoknKAzMrxh94c0kn5hOlBYeeaFdzrlqxt+W6JkjROZpcO
         xir1ANMZekcmjjHqtr9B4uRqdxJhKR6I3VaIAIJ+D6Mtzy87y0NsYzuGScqD6V+QdoB6
         38aEhn3cAsnmBup4O5GS0tI9xrtdFMurRuPmVUPh1Ghrss0ICI1IF4HeUHFT2vqf7N56
         /8EhPmBJsKyVKPU3iYyoBBNAaNvRtA+WpuQbClmTqTRuvy8ZUAiQ7Lb1lXrPRWGna76Y
         TIuCTyJx+4lvegMCgS7WQA9UWoTuysrXM0NrK2nij0JWQOYOh/bSOQynfrJfHn3zXxEn
         W+tg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=CeDlAGAia2UdxJTVydg7YSvSL6VAEJ9ryAg8tAKqBzs=;
        fh=Gli6+4ZF66H7uWxiyf/JpBu1n4zTKnAUJdhFx5twkLk=;
        b=gVmTNoBQyrQtMRoD8Lg8zA3Kdf7iGmJDRptauug6Yoor3vpUTl+bG6+RMDJ8teCI0e
         U54VWToALXiANsleTZrgFXZNrtc8K9cc4QZ4YSpbR8vqzIVPhJqN6r9QdgDX8i0G0PR9
         ok9yIbqpHsWgQWwlEUBzmSNEPXBREt46Pq7L1DFenM1UAIrpGx0afqtm7xS/jnAtnooC
         l9cuEPNUJ9RxR2ZSHGMhx68heejpPYTHU4qkaBIHFSJEwD1v+12zn0Y35L2mj7cRRp1O
         9r9UD/cnE9vQuHvBqgUNxvb1+GushbW38Hvjwj9Q8aZFi/1xEGKuxwjQY2Udg2SnoKJx
         Yeqg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=V4Ho81Se;
       spf=pass (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::135 as permitted sender) smtp.mailfrom=snovitoll@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1750855867; x=1751460667; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=CeDlAGAia2UdxJTVydg7YSvSL6VAEJ9ryAg8tAKqBzs=;
        b=HQA0FDvj8vk/gzJrj57PsbgtBlOhywFc/lStCGg9rKXIE6Dt2JGP6nF5L+GoF3b3Sh
         doKFWl9PFHyKBEUOHNNYj1GYMHsRDJNCge7jXU2jBYXOnsQOMx/MUJPV+ZKO/3dlLqGA
         IUjsP/LTYSNiJVaJ2LVKcfFiq2rVsMSokgGTZp3nkmklH8A8zbbnFZep8N2de4vJD3CP
         5zU/8MprgOr16QrDEnezJtaDJczobFIKNPR18dXcbwdvMVbeIF1SotI112IHiBaIi4IF
         sVZxtdVTK8vGwU2wKQ0sbU+Es0/TLEjW54Puh+iunJTzA16E0hXCEe3sft8Fz58AR7IY
         /ppw==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1750855867; x=1751460667; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=CeDlAGAia2UdxJTVydg7YSvSL6VAEJ9ryAg8tAKqBzs=;
        b=OrqpaVR6JKkJ2g/6L2PtdyvlIBhH0529WSnZERa3KisU8Ol8aa+9PSAuRhoNCjcNbA
         rPCizsCddgUXAHBNjmTOBSCRHFkjdKpstP79Bz0J+9sP4lrfiao29Gw8P5mwkP8P2h5t
         tqzgwcivMeed4AdsArdggAkjlrHH2tfDZqyQvDwo37pOElyQvoSYUmMup/RmGx9BC783
         KWU6JhZ509UbnPqKN0jKiI+r0X6aGQboIy1K7Jo+0tIrY1XE0rNtMycWRYmbFVruOQGV
         tfVkj/LIUZMwOHk8PDDKXYT0OfB38RKZjj9YYhdI9SF7o8d80CFFeveSxgido1Pxf3DA
         SsBg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1750855867; x=1751460667;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=CeDlAGAia2UdxJTVydg7YSvSL6VAEJ9ryAg8tAKqBzs=;
        b=ldbBjeDRwI9Ig5/pKm0W0o8kw7xs3iTTmed+oT2h5dRtsBE6GFdNzT3gRPjkTWRFy2
         dZZzVOZfWeLMmS9bzJlxUq9WBrZ6uAyo7IEr7zYksJwQoMGXHJOGoLL0tSdxmjuMSGNv
         FGiPPRRE8KcOHAlwpp9fLsxxD6ikXw3722VvBgj0jjdFV3U6gP1kzyHyMywWjUIF7Hga
         YVX0tbFu4112BXScqL1G7GU25Dga1CrTB0qXZbjTB07n0hMiXa6O/t81WcWPpq1qDUbN
         oLynOxP98569ChLQ9Q1N7ct0lZdghaBI0PUAeGh94Ev2H5vOO64SwUR3oLw+qTSr5SKQ
         2Vzg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUCL4JExa3s/gFsQNtggRXbNd8soqK52Ao/xNXunOm8oqbgD1hvIHqEAQxqSFS6SssthjRjyA==@lfdr.de
X-Gm-Message-State: AOJu0YwAQiqxEQvNWkkSs4G8gxL+gvWEpOvkyUA+p2sMz/a7rM0dEP4Z
	W6YyYoRqi3pkSytI1cPthGe4sajyWJPIeJJO80z0FDwjKmj1zNayzNtu
X-Google-Smtp-Source: AGHT+IFD3fFitv1bEr+I8murF6IC65+6DYyomJru2tD9DaLPJcfW4r0sJg+4cW+gp5ERw2ryY1GR0w==
X-Received: by 2002:a2e:a4b6:0:b0:32b:8778:6f06 with SMTP id 38308e7fff4ca-32cc64fe7edmr6859531fa.18.1750855867134;
        Wed, 25 Jun 2025 05:51:07 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZfg0x0aMf5aRXHe1B6LKRS5rdDggVHzpcnSevdsbpcWWw==
Received: by 2002:a2e:a4b1:0:b0:32a:6c94:9a22 with SMTP id 38308e7fff4ca-32b89705ac2ls9716891fa.0.-pod-prod-09-eu;
 Wed, 25 Jun 2025 05:51:05 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVSDKjv6NMTb8+6n81ydpJwNVIMyLmpY2lJEYr0jjamso+sMliTG4INn6KncP3KDPZGL4aO1jNdCQI=@googlegroups.com
X-Received: by 2002:a05:651c:4081:b0:32c:ab57:126b with SMTP id 38308e7fff4ca-32cc64d312bmr5647211fa.16.1750855864577;
        Wed, 25 Jun 2025 05:51:04 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1750855864; cv=none;
        d=google.com; s=arc-20240605;
        b=YRgv2yePf6zVr6rFEiO4O4/vM+NZgFpHLewGtxIqfcuasL5QfvDrpjQCMdUYKE+Jrh
         oWyzDNbFaSZx5Vn7lz6ulw3QU6gTzZIPXV3hfJUA8tHx1v9V52933e1iPlQvwLAAGI/e
         V14PiGd4dFWfd99Ypqo7Cee1JeyD8BNtaXG1CVU04pb0SBgG2uSpkkK2N+4Yd59IOnm5
         +/SBPXNhHGVVa51vlUQTE+J7AmxAG6Tv3rlSgfcLVvw32xc3J2WwjD4ohI87sK1ugX62
         YyaN/dsZFhp+7i2swLaOMxhNOzJ+7fbugHAuWysYONeXh8cdag2obt+oq+QMci08qQmD
         VJXg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=CRwRhM1MtMEUcOGQgquJfle4LDepcccXWla+ZKxsdwI=;
        fh=oGrIz8em8L/5txuI/si8JwcMtDwpiE6I/WKM9f8BnLc=;
        b=liumA0fRoIc+SIStY7G/1h/U+N/8D4apPZEt3TIziunqufwVUDCBMf35db+HPZYihk
         JZEbeU+hq8oarRPl41r1EopKVCo6/lj/9sSz/blA0IaDCZ0tl9Lg+D7S3UIcsu7z/nTk
         VLoec+39IUE3zYDp5/GwTrlMX3pFo+UfhNnX6TkatUcEQ++gwfzuMpajtbSbpsZsCVax
         +nur23zMUzDNFTWbTJtWNyBnp0daU84LSlzi8PI7le242e3SGRWRC5epm8dsb4gDjBH5
         NGuIAL1KqNZ6rYQmQ78+p8GOmbMmaCIzWP/fqeoPoq+HMH8MUaOTcdS2rWcGy9yyD8Ga
         TslA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=V4Ho81Se;
       spf=pass (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::135 as permitted sender) smtp.mailfrom=snovitoll@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-lf1-x135.google.com (mail-lf1-x135.google.com. [2a00:1450:4864:20::135])
        by gmr-mx.google.com with ESMTPS id 38308e7fff4ca-32b980a016bsi2773401fa.3.2025.06.25.05.51.04
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 25 Jun 2025 05:51:04 -0700 (PDT)
Received-SPF: pass (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::135 as permitted sender) client-ip=2a00:1450:4864:20::135;
Received: by mail-lf1-x135.google.com with SMTP id 2adb3069b0e04-553b3316160so5027757e87.2
        for <kasan-dev@googlegroups.com>; Wed, 25 Jun 2025 05:51:04 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCXkUX96qHuQVH7cTKQ3yUs3/o4FPjFUXB7XL0Ig+PxRybtJpvxNnwyYY6p+GA1jVCYBXaM7XcqdRlg=@googlegroups.com
X-Gm-Gg: ASbGncsdsoBfy+P0elui2AkCBsjL5uSHzSfgAQcuDoEnQraW351wmSU8uvJkBYtXh1j
	MpL2KCAWrHsk07Wmm9kBpq2UccnKx0CFxiKryD0Ce0bhW70YEDp5foktxPMQOJGxrr4msGH6DSg
	L4mNbIaZSsN8lrKWICQu8b7cE1XMkjPPQwPy3KrXsMmw==
X-Received: by 2002:a05:6512:4011:b0:553:297b:3d45 with SMTP id
 2adb3069b0e04-554fde58124mr1020525e87.43.1750855863865; Wed, 25 Jun 2025
 05:51:03 -0700 (PDT)
MIME-Version: 1.0
References: <20250625095224.118679-1-snovitoll@gmail.com> <20250625095224.118679-3-snovitoll@gmail.com>
 <750b6617-7abf-4adc-b3e6-6194ff10c547@csgroup.eu> <81a8b60be5b99ecd9b322d188738016376aff4aa.camel@sipsolutions.net>
In-Reply-To: <81a8b60be5b99ecd9b322d188738016376aff4aa.camel@sipsolutions.net>
From: Sabyrzhan Tasbolatov <snovitoll@gmail.com>
Date: Wed, 25 Jun 2025 17:50:46 +0500
X-Gm-Features: Ac12FXwt1iee6Yaba3PMavifTn-RFaMv0HhE7s3qnJv0p52DgpRl1n7RcMDkzZs
Message-ID: <CACzwLxgCH6KuVDRS3d9MrmA=wY_rMA6R5TPB_v37BkD8-A9yuw@mail.gmail.com>
Subject: Re: [PATCH 2/9] kasan: replace kasan_arch_is_ready with kasan_enabled
To: Johannes Berg <johannes@sipsolutions.net>
Cc: Christophe Leroy <christophe.leroy@csgroup.eu>, ryabinin.a.a@gmail.com, glider@google.com, 
	andreyknvl@gmail.com, dvyukov@google.com, vincenzo.frascino@arm.com, 
	catalin.marinas@arm.com, will@kernel.org, chenhuacai@kernel.org, 
	kernel@xen0n.name, maddy@linux.ibm.com, mpe@ellerman.id.au, npiggin@gmail.com, 
	hca@linux.ibm.com, gor@linux.ibm.com, agordeev@linux.ibm.com, 
	borntraeger@linux.ibm.com, svens@linux.ibm.com, richard@nod.at, 
	anton.ivanov@cambridgegreys.com, dave.hansen@linux.intel.com, luto@kernel.org, 
	peterz@infradead.org, tglx@linutronix.de, mingo@redhat.com, bp@alien8.de, 
	x86@kernel.org, hpa@zytor.com, chris@zankel.net, jcmvbkbc@gmail.com, 
	akpm@linux-foundation.org, guoweikang.kernel@gmail.com, geert@linux-m68k.org, 
	rppt@kernel.org, tiwei.btw@antgroup.com, richard.weiyang@gmail.com, 
	benjamin.berg@intel.com, kevin.brodsky@arm.com, kasan-dev@googlegroups.com, 
	linux-arm-kernel@lists.infradead.org, linux-kernel@vger.kernel.org, 
	loongarch@lists.linux.dev, linuxppc-dev@lists.ozlabs.org, 
	linux-s390@vger.kernel.org, linux-um@lists.infradead.org, linux-mm@kvack.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: snovitoll@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=V4Ho81Se;       spf=pass
 (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::135
 as permitted sender) smtp.mailfrom=snovitoll@gmail.com;       dmarc=pass
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

On Wed, Jun 25, 2025 at 5:24=E2=80=AFPM Johannes Berg <johannes@sipsolution=
s.net> wrote:
>
> On Wed, 2025-06-25 at 12:27 +0200, Christophe Leroy wrote:
> >
> > Le 25/06/2025 =C3=A0 11:52, Sabyrzhan Tasbolatov a =C3=A9crit :
> > > Replace the existing kasan_arch_is_ready() calls with kasan_enabled()=
.
> > > Drop checks where the caller is already under kasan_enabled() conditi=
on.
> >
> > If I understand correctly, it means that KASAN won't work anymore
> > between patch 2 and 9, because until the arch calls kasan_init_generic(=
)
> > kasan_enabled() will return false.
> >
> > The transition should be smooth and your series should remain bisectabl=
e.
> >
> > Or am I missing something ?
> >
>
> Seems right to me, it won't work for architectures that define
> kasan_arch_is_ready themselves I think?
>
> But since they have to literally #define it, could #ifdef on that
> temporarily?

Thanks for catching it. You're right. I need to change the order of patches=
 :

- kasan: unify static kasan_flag_enabled across modes

, then we should apply arch specific changes
where we call kasan_init_generic in kasan_init.

- kasan: replace kasan_arch_is_ready with kasan_enabled

>
> johannes

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
ACzwLxgCH6KuVDRS3d9MrmA%3DwY_rMA6R5TPB_v37BkD8-A9yuw%40mail.gmail.com.
