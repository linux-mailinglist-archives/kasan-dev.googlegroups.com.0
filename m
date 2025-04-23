Return-Path: <kasan-dev+bncBCCMH5WKTMGRBZWQUPAAMGQEIN5DOYQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3d.google.com (mail-yb1-xb3d.google.com [IPv6:2607:f8b0:4864:20::b3d])
	by mail.lfdr.de (Postfix) with ESMTPS id B1AAAA98AB1
	for <lists+kasan-dev@lfdr.de>; Wed, 23 Apr 2025 15:17:28 +0200 (CEST)
Received: by mail-yb1-xb3d.google.com with SMTP id 3f1490d57ef6-e7289e1e03dsf7236254276.1
        for <lists+kasan-dev@lfdr.de>; Wed, 23 Apr 2025 06:17:28 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1745414247; cv=pass;
        d=google.com; s=arc-20240605;
        b=PGvhzFKEFyBjgDpqsdB/a7NjJMaYp1lZmpW2/4otBYqMIprk5yQAlwS0fPekomZ++i
         +QpikndZK0R1vlBGkh1M+STvVG6SuxJIU9xyPi5fG6R9PYCrm2eUNp/tZ/gwxdbdlgj+
         oWJN2NPmEfkAtE6DCNCNQCRpSizmiJ+jE+isGXoDjnBCcEP4DMFcl6xjP02e4lTp4JH4
         INAhFBr1rc1dOS06cD1nIs/fkuzcp5y4CqmLXsJCI44ENROMi85G9PEOYth5nm/bSj09
         evrAVxBaonf2FnI+VZo2qjoZryKYjKML1r1fH7IbOmMoSzyK4Xr2LprKhOxX3IeiZ/wd
         zoAA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=tlRdacbH0QRmAqTPBfkGpTcZgC4OrzyY3srSlykEkxE=;
        fh=s9OCRtgFUs0Vt02XdqhwMFLWqo5Ytja7BJNyhMGuUSM=;
        b=kQHHzoLw5qXAd3+3F26d/s6aJI3+owfbyKhDZ1WXBLDTCFBAEWsChMyG8+lVDGTw9Q
         CTgq9p1cSu1cOJxYq9Y6zF5R/635Tb0Sr8fgMvAV3kUXGPWOksJ8MD780yqwY3AYIypo
         TInpy87tpPzVSlpuM4kNiD+gqh8J8eZnG6Igs1s/Y7sAWmwk7VFezBF9gJNsCff0FC6H
         Yd2S8erJXQG3e/5mQUvAdtoRPDP8MXEj2VIAvGn6SRE7ca3dq+poARjrGgzlaMFyOE0q
         eIv5IlEGp9D5H26368jp5nw4bzk0IOtdGocnR45RjfhDKhbtCOj9VNZ6GKJkcbxiLy9Y
         BUGg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=DpFyGTwl;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f33 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1745414247; x=1746019047; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=tlRdacbH0QRmAqTPBfkGpTcZgC4OrzyY3srSlykEkxE=;
        b=tC6gQPo92ABgk0e9gfXu5ARMQOP/9JAFdr6+yZfEoZ4SI/EQAPLqaQYF0OvIcUhddf
         0o34xYyMwhuNhzMyRXYbOE9ADE5Au/Ml2wyCnErd7bmQczOnKVyUFOnAGYPKzDKpkRtr
         q0mDWCAf2Yjt95kWSQf+jwEIAftutvysc93cp2CUg25zaP5wigDANiIEWP7YjmVmobse
         rxuab8j43ZpOaQK9/bEQJfAcRyVP+qkQR61gPy6rjNqCv2GlktOrM8SP4fabD8LnvmRj
         Djnyayl+LRQX9VmkFS9dsK4tVLqTBDNG+TE4YCmv3YhjZpdCN0jGOxUFSaH7K1zEAnyJ
         G3NA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1745414247; x=1746019047;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=tlRdacbH0QRmAqTPBfkGpTcZgC4OrzyY3srSlykEkxE=;
        b=tlNcHGBXGTDhLyiX5kefGB6h2+9npTIrI7NG2otz45QyiVmNGXO0GsB7vP9FTxEpiq
         l1UlzF1+vMpsw1U19uQKcVkXNWFhxcjbQJmfDdLCK37exOgLG9wiMXWNwTJMQ95H+ElF
         Fah6z/w7Tp0M99qYytr+nZ9ym0UwLjlptWfuwE9nEzsuktVgLy9Wb0+C+nd6X1DSqpOg
         IbqmsOSIgETNnYnyWZJ7LZyTnPQER7w2VOo72a0nKAZPTG14hVRwCmRjPM4ut7FGedEZ
         est7aubZ55bSv/Y/16aczaG7DhNMdhw3lTH1W8s+U0JCsZTDfyGMcMFgzdXWfq9fMsxe
         IaOA==
X-Forwarded-Encrypted: i=2; AJvYcCXFJce9LsedSCSnxJXAph1dgQdeZt6BWXOD0kcpQQhk3xIPiIEbode2gvBg7dW+U+XWTVlWsw==@lfdr.de
X-Gm-Message-State: AOJu0Yyg5CDgz5EfSeJ+HSppv5feftR92QGF5w2KsWoyjbPpYPYf6g+4
	d0l1bj0ceHsdNtA81RROlgFaJLDH+yN1VAsFptFwctmB2X5/vake
X-Google-Smtp-Source: AGHT+IFw7vwibrruX7sNZTy5Jyc57DKj5jAFJC4VH71rtY8aht8lGdZifDPIT5Kgu4CEKTaxk3Eg1g==
X-Received: by 2002:a05:6902:20c1:b0:e72:824e:de61 with SMTP id 3f1490d57ef6-e7297ec4854mr24689624276.37.1745414247197;
        Wed, 23 Apr 2025 06:17:27 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARLLPAI6jGNO40qLhv1SkPD9mHImMv96H+QwLcoNlja+hQYfyA==
Received: by 2002:a25:aa8f:0:b0:e60:8883:5aa4 with SMTP id 3f1490d57ef6-e72805040e5ls403554276.2.-pod-prod-03-us;
 Wed, 23 Apr 2025 06:17:25 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUE44F8XvYHG+jsc0YNTB7UsrshCfjSdi5Z6iYMmJX3u+tIBZqFG1v4fJl5dncvxW5FfJHGLYswUHI=@googlegroups.com
X-Received: by 2002:a05:690c:350f:b0:6ef:77e3:efe6 with SMTP id 00721157ae682-706cccfa80amr284071367b3.13.1745414245496;
        Wed, 23 Apr 2025 06:17:25 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1745414245; cv=none;
        d=google.com; s=arc-20240605;
        b=iaF5JdzTRF2oUqmjLoyVu8w9TYZwiR3hMkVcRbtobpV+A4A4XRCZFkmlMIepPLDpIB
         WWN6qQ5oh9z7vbi4OohV7N2aPkTVcoIqbjYu2unWoBsgJgwDp2dz1A9pPU7MCeJvfPyI
         wyBrTk0GZipqv9uleXWz285ZVwAalP4aU4WKSjV25MBFaBwLOvtR2xymcKeBD4pb5zp3
         iRvJ5gNSrLN/zE9uDmU49NaGjiHZ9FrCZ09LL/w8d179sBBbNR1ad2gw2rR1p8WU0hYh
         j3fzgpnsMuCYZtn6bN+ig5lPOyWZRO+kzUGlGdOK9vsgbCwhKDe/TnnqlJxGwowsdyzQ
         PD0w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=47n91vIA+7F3IZw3KWGYOVVfAlHkRgnHFR90Rbj0tB8=;
        fh=Rr7kStc4Wz9UmRQ39utglOyfU50BgGa2M20ig5VUYSY=;
        b=PIDvgPcZuPirNqovv4QA1JHowC7cYroHasOy19G7s75hTGaG6fCGhzmmcCk1dNPadl
         YrobSE1t+ytGPJx5P6yqCiMRAHbuiG06pIc2nDfCChyhvVVOhEyLia+FihhgOttUDdbU
         eoOjgFdRyabXgVXTQRQLI20R5mRpjRXxMoz32V42CEFg8eHYv9aHYUIqtw0chRQ/xZ/b
         0b19feQUrbPb6zz3/JkmRREjLetXUUcek19AkgSfx7hr1V23Vb9DZnQG6YaSH6rkTtWP
         DVKtJdmjZL2jrj3SR7zuZO6pDzGalkJPT8bqTkOBdpx8zEDpIDvYgzjsouhzotBsx/hu
         K1mw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=DpFyGTwl;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f33 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-qv1-xf33.google.com (mail-qv1-xf33.google.com. [2607:f8b0:4864:20::f33])
        by gmr-mx.google.com with ESMTPS id 00721157ae682-706ca537fb2si4947277b3.3.2025.04.23.06.17.25
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 23 Apr 2025 06:17:25 -0700 (PDT)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f33 as permitted sender) client-ip=2607:f8b0:4864:20::f33;
Received: by mail-qv1-xf33.google.com with SMTP id 6a1803df08f44-6ecfc7ed0c1so58328786d6.3
        for <kasan-dev@googlegroups.com>; Wed, 23 Apr 2025 06:17:25 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCV1abOOPU7nOLBJgD/xjYHIQ5saytwp9bTVMAhovHrrtBkhI3ru82ZojM59ukqZSpFn8hSpPxLdzsw=@googlegroups.com
X-Gm-Gg: ASbGncvGihOL5xDzzZc4ZEZnREoYAMppvDnuyISCW6fivjFSjLtvkCMLgGMu6Rsys6h
	pkx+wVDwl/ZBy1lYSLFNktBnEUvVlaYub0tIGW055x4wjdE5KoAd5utCs891MrsZvRMABYNFSL5
	gpJmOolX0D93SoPvSAdKRUFhUGgv9Dk/1SHQO4DLuUtAxnhHqoaSOHMTy9wYXVbA==
X-Received: by 2002:a05:6214:1c47:b0:6e4:7307:51c6 with SMTP id
 6a1803df08f44-6f2c4664a1fmr345097686d6.34.1745414244765; Wed, 23 Apr 2025
 06:17:24 -0700 (PDT)
MIME-Version: 1.0
References: <20250416085446.480069-1-glider@google.com> <20250416085446.480069-6-glider@google.com>
 <CANpmjNM=AAtiXeDHgG+ec48=xwBTzphG3rpJZ3krpG2Hd1FixQ@mail.gmail.com> <CAG_fn=WD3ZuJCQ4TiVKXLhn5-=tsaW0d=zrM-TuEokP5zEvOSw@mail.gmail.com>
In-Reply-To: <CAG_fn=WD3ZuJCQ4TiVKXLhn5-=tsaW0d=zrM-TuEokP5zEvOSw@mail.gmail.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 23 Apr 2025 15:16:48 +0200
X-Gm-Features: ATxdqUGP6Sm5jILBJHeySVhpgt2vOiTNYZA_rN6aN2uLH5lQDDhJQbQKZx7QM4c
Message-ID: <CAG_fn=UrJGBcmqYkaqy3qckg=vVQZ4fA2cwruSnCdphkP0ZoZQ@mail.gmail.com>
Subject: Re: [PATCH 5/7] kcov: add ioctl(KCOV_UNIQUE_ENABLE)
To: Marco Elver <elver@google.com>
Cc: quic_jiangenj@quicinc.com, linux-kernel@vger.kernel.org, 
	kasan-dev@googlegroups.com, Aleksandr Nogikh <nogikh@google.com>, 
	Andrey Konovalov <andreyknvl@gmail.com>, Borislav Petkov <bp@alien8.de>, 
	Dave Hansen <dave.hansen@linux.intel.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Ingo Molnar <mingo@redhat.com>, Josh Poimboeuf <jpoimboe@kernel.org>, 
	Peter Zijlstra <peterz@infradead.org>, Thomas Gleixner <tglx@linutronix.de>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=DpFyGTwl;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f33 as
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

> > >  void notrace __sanitizer_cov_trace_pc_guard(u32 *guard)
> > >  {
> > > -       if (!check_kcov_mode(KCOV_MODE_TRACE_PC, current))
> > > -               return;
> > > +       u32 pc_index;
> > > +       enum kcov_mode mode = get_kcov_mode(current);
> > >
> > > -       sanitizer_cov_write_subsequent(current->kcov_state.s.trace,
> > > -                                      current->kcov_state.s.trace_size,
> > > -                                      canonicalize_ip(_RET_IP_));
> > > +       switch (mode) {
> > > +       case KCOV_MODE_TRACE_UNIQUE_PC:
> > > +               pc_index = READ_ONCE(*guard);
> > > +               if (unlikely(!pc_index))
> > > +                       pc_index = init_pc_guard(guard);
> >
> > This is an unlikely branch, yet init_pc_guard is __always_inline. Can
> > we somehow make it noinline? I know objtool will complain, but besides
> > the cosmetic issues, doing noinline and just giving it a better name
> > ("kcov_init_pc_guard") and adding that to objtool whilelist will be
> > better for codegen.
>
> I don't expect it to have a big impact on the performance, but let's
> check it out.

Oh wait, now I remember that when we uninline that function, that
introduces a register spill in __sanitizer_cov_trace_pc_guard, which
we want to avoid.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/CAG_fn%3DUrJGBcmqYkaqy3qckg%3DvVQZ4fA2cwruSnCdphkP0ZoZQ%40mail.gmail.com.
