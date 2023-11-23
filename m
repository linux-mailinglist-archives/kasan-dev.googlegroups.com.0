Return-Path: <kasan-dev+bncBDW2JDUY5AORBZXS7KVAMGQEKSYOD7I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x839.google.com (mail-qt1-x839.google.com [IPv6:2607:f8b0:4864:20::839])
	by mail.lfdr.de (Postfix) with ESMTPS id 4DBBF7F566B
	for <lists+kasan-dev@lfdr.de>; Thu, 23 Nov 2023 03:31:04 +0100 (CET)
Received: by mail-qt1-x839.google.com with SMTP id d75a77b69052e-421a7c49567sf93111cf.1
        for <lists+kasan-dev@lfdr.de>; Wed, 22 Nov 2023 18:31:04 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1700706663; cv=pass;
        d=google.com; s=arc-20160816;
        b=D47a5HKSe5yFuVrFUwioLZJDhyDZZaU2Ml+FB8ig3gcj/GZZpuZnwyZCnmVqjdHUeA
         L2S3OTpzpTL6Y8TMq7ROd7CP42NCE4vboYavfKBgVpZJfesLuOA6Ol2WgMG2d9WEW0Yl
         vXI1CWLEXleBZx0S0TA+jnPtbNQ7aX1L8bbJ6dWXDHVawOfpPgI01jhJXQ5zTkLo/C1O
         XK+rYKU9gRwfRo50bVn8mU5XiWIewZ3S1aBkCPUsPeNEEyY/322aNyfiSDCl3XhwOIiQ
         2OSzvQmuomupod82UL6rB54K2Ngt4HQEIlDV8rjCiMGrErs0F4vgnu76V7kuRMJRpQ1C
         Wg0g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=7cVwCY4k1xt1WVN62x4647afoFW9XNhaZwtE/O0BBsg=;
        fh=DMpuiuGddKAd9gJK1ZWZ3xeGsMHnmViVLNra/uemh1o=;
        b=cC/XKS4SU204rY1XbS167uKWTM/11GALx9ggj6uqdArGOdKMG13P8kKrhK8axJ5fmx
         IIUmOd/1LlycuFmZnWTnQP9UZqS62jMrbGfOBNhcVHQcLrVdiaSLhMCpxe1IaOYwSb/4
         ingYYOh4qtaBxKQV/QM67yHZhgyjLiM4zkHzQeCMo2h/NZxgRW5FfYmGxLd31H8DmEdp
         f3WCQRJTdfq1umoWIxoUS9vhcP6V+BZqgpLebmzYDBAsOgIXoj207r/sbKrjxAe2ZmvL
         8agW+q5bfnDwdZwjC9L3cGXtFlNH8wtrm3lM7k4MgW0syLVpPGvzxTrPRj1jcoQOG8TO
         3vcQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=FmXWgVje;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::52f as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1700706663; x=1701311463; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=7cVwCY4k1xt1WVN62x4647afoFW9XNhaZwtE/O0BBsg=;
        b=JseuxvKyrCOzu+Hbl74TQpjy5aFBP3HOI5FV4ewapf9ZyFSjaFCfV03gep7RscxgEM
         l0Xzt2ZlCsN8vbzirNG6dJQ6lJXpUHR6JG/LkYvzgCJHypFty1FddvqkEpB27wkvnYBF
         Q0YUWjLEKjhuDxM7G4Q40+6DW1/i1cQlfhPaxdFILNgDles6ZeRayNvY+DPhDRlo97oz
         Wlm9MGA7r5M0X0UWezgl+ZLWbtq3OK8TM1wFOCfsfUFJkbqmZ/WmM65BbEVifC2a84Z1
         rhw4XbYwu/QDoMg6UHtEMdA2XeEBlPdfs2P6IyQmszGEDhBqUXleq5SlOA+oXTtinPBY
         emBQ==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1700706663; x=1701311463; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=7cVwCY4k1xt1WVN62x4647afoFW9XNhaZwtE/O0BBsg=;
        b=kzxSlTNagSxplEpswrl0k+TWIbFL8EHpzoP+MpKggbi7M8kLHyYKA0guw9i/JmlLKB
         OGK4vZefGu+Z6tihHOdsBQhwITFD/8MrLKNKp/WOisKp9r5ZAYZkU8NwJE76Z8eiZqwK
         MOhRJQ/Dt5769wzAOhtMPpHfvdxHaYIqviUjH8J/rXjDWphhJoz4PNHGCAyS8wTEuFvf
         55jDuDIY9W35/jI7WgMWl8uPqChrGcBe5vyS0SJY+6cCReLrtgowCcRkOHlP+rpalHyd
         5YAEkw0Gqv35Xyw3yenltFP3jaCZAETCrz87SK+ix87FxgS5n4ycAl/CioWfsLrCviRd
         YQcw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1700706663; x=1701311463;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=7cVwCY4k1xt1WVN62x4647afoFW9XNhaZwtE/O0BBsg=;
        b=TgzleP1dfiCVWExl0nmINIUJ/lgYQOPXZL387EhwRFFmnlC63UywOnq2LhMZqZ9PSJ
         q7r4mxUOHyQECEckpPNCT3rMCfeYQxMyEu8VSmJOtU4gJADG9z9EdtWbLhW6lj7jRAOL
         MM14ROxDbSE/aD7bEmye5cWDH3yV/0z7UB7cnAZURmFOdrSDTBc7WhV4Ti+GezZ5f97n
         30hHkoi9Xr+jCQozqIfDsRqNH6oyp/7nocoSX/bGE3CZ/jbq8rc5/I/A5y2AmkvtpBr5
         6nZt+7aExZC6B+3Hu5UfjepRjpdyopNj1ZOG7RK3XNcKZHOXm0ImXWtPV/B2QynngECO
         w0Wg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YyYW+uXWoM0Y+oMo97Nx31FSnziUkUwSAqDQuNH1eqFjQ6F5iLg
	ECRQgeelRZ0CN3qMvxC81Xk=
X-Google-Smtp-Source: AGHT+IFarF9WgT86FNrua89r+Ig4j7gYrj1QtJKY3+N5VWA8N4Wwb1Ztzv/Tw3rT4eOlrFY7KhM/hg==
X-Received: by 2002:a05:622a:18f:b0:423:755f:ee39 with SMTP id s15-20020a05622a018f00b00423755fee39mr284190qtw.27.1700706663022;
        Wed, 22 Nov 2023 18:31:03 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:ad07:b0:1f9:517b:1136 with SMTP id
 nt7-20020a056870ad0700b001f9517b1136ls98615oab.0.-pod-prod-03-us; Wed, 22 Nov
 2023 18:31:02 -0800 (PST)
X-Received: by 2002:a05:6871:7505:b0:1f9:8f0e:1c68 with SMTP id ny5-20020a056871750500b001f98f0e1c68mr4310675oac.35.1700706662432;
        Wed, 22 Nov 2023 18:31:02 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1700706662; cv=none;
        d=google.com; s=arc-20160816;
        b=lYwIXMXEjhDhppnVBtKIJpJR8nleXw1aYfcow303HhEPwJon/yEOzkzvLmgDJADPPz
         oTMq1vgT2KBSi1mWnGHeij3bRAkjEMGXz9YBa46htGqhbpxGwey87mbBfm1ORhQkm0v7
         xjaFYfI6oQzsPgBh+yS5wx5BfgaGDEX5mpOK5dnyn2sw6kOVhVFQCRPWuV0pYd7Ti/1D
         WsRsxDFiKf8Geg12UcH6hWMemFn1hfJtdSuayJ2DfHtEWBn7YkXaahxWrSrigd77zcDt
         IHlBubZRjXhsYo6wzSaG7YB9goHF8fInStPuduhFCWL/CAkBiPC9p+8UcCEXvs3YGBhI
         Bi9w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=U7iDnp8t+KdyeiUT7D88qTOqMxvRmmiP2r4q7q2VrCw=;
        fh=DMpuiuGddKAd9gJK1ZWZ3xeGsMHnmViVLNra/uemh1o=;
        b=AmH+edRElxNXW/SxmzJaBykKuDar8j12KbYYTRBb7IayimzdG5stc5rz1cEmZ3+M60
         Vql9qJkUKqpT6APCVgtLiFLM6ZfLyPYvkftN1U/BAsP/LVghmbMoVHN1IOSKwC2Q26+s
         qU1yYM1OMT+B4+taygqwmKOXfNc6kumiL8TI0lAtOptPPdoy1KBXLPDYIYH3ktvm7gtT
         nd5RSEfSP9ikWuphePVPdyENZc82W+jW1Qv+rUQA8PP4ds+gYbhnIdnW8kuh/Ho1TbzO
         BRiMtt6rEajKBrHRGanCCUou6QsMSfcfWP5BUQ1eOr4ln2JvONjzXfq/j89IxMg0dUmW
         Zc9Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=FmXWgVje;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::52f as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-pg1-x52f.google.com (mail-pg1-x52f.google.com. [2607:f8b0:4864:20::52f])
        by gmr-mx.google.com with ESMTPS id s35-20020a056870612300b001f954907295si15756oae.5.2023.11.22.18.31.02
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 22 Nov 2023 18:31:02 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::52f as permitted sender) client-ip=2607:f8b0:4864:20::52f;
Received: by mail-pg1-x52f.google.com with SMTP id 41be03b00d2f7-5c210e34088so288643a12.2
        for <kasan-dev@googlegroups.com>; Wed, 22 Nov 2023 18:31:02 -0800 (PST)
X-Received: by 2002:a17:90b:4d05:b0:280:c0:9d3f with SMTP id
 mw5-20020a17090b4d0500b0028000c09d3fmr4312829pjb.34.1700706661646; Wed, 22
 Nov 2023 18:31:01 -0800 (PST)
MIME-Version: 1.0
References: <20231122231202.121277-1-andrey.konovalov@linux.dev> <CAB=+i9QFeQqSAhwY_BF-DZvZ9TL_rWz7nMOBhDWhXecamsn=dw@mail.gmail.com>
In-Reply-To: <CAB=+i9QFeQqSAhwY_BF-DZvZ9TL_rWz7nMOBhDWhXecamsn=dw@mail.gmail.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Thu, 23 Nov 2023 03:30:50 +0100
Message-ID: <CA+fCnZdp4+2u8a6mhj_SbdmfQ4dWsXBS8O2W3gygzkctekUivw@mail.gmail.com>
Subject: Re: [PATCH mm] slub, kasan: improve interaction of KASAN and
 slub_debug poisoning
To: Hyeonggon Yoo <42.hyeyoo@gmail.com>
Cc: andrey.konovalov@linux.dev, Andrew Morton <akpm@linux-foundation.org>, 
	Marco Elver <elver@google.com>, Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Vlastimil Babka <vbabka@suse.cz>, kasan-dev@googlegroups.com, 
	Evgenii Stepanov <eugenis@google.com>, Oscar Salvador <osalvador@suse.de>, Feng Tang <feng.tang@intel.com>, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=FmXWgVje;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::52f
 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
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

On Thu, Nov 23, 2023 at 1:39=E2=80=AFAM Hyeonggon Yoo <42.hyeyoo@gmail.com>=
 wrote:
>
> On Thu, Nov 23, 2023 at 8:12=E2=80=AFAM <andrey.konovalov@linux.dev> wrot=
e:
> >
> > From: Andrey Konovalov <andreyknvl@google.com>
> >
> > When both KASAN and slub_debug are enabled, when a free object is being
> > prepared in setup_object, slub_debug poisons the object data before KAS=
AN
> > initializes its per-object metadata.
> >
> > Right now, in setup_object, KASAN only initializes the alloc metadata,
> > which is always stored outside of the object. slub_debug is aware of
> > this and it skips poisoning and checking that memory area.
> >
> > However, with the following patch in this series, KASAN also starts
> > initializing its free medata in setup_object. As this metadata might be
> > stored within the object, this initialization might overwrite the
> > slub_debug poisoning. This leads to slub_debug reports.
> >
> > Thus, skip checking slub_debug poisoning of the object data area that
> > overlaps with the in-object KASAN free metadata.
> >
> > Also make slub_debug poisoning of tail kmalloc redzones more precise wh=
en
> > KASAN is enabled: slub_debug can still poison and check the tail kmallo=
c
> > allocation area that comes after the KASAN free metadata.
> >
> > Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
>
> Thank you for looking at this quickly!
> Unfortunately the problem isn't fixed yet with the patch.
>
> I applied this on top of linux-next and built a kernel with the same conf=
ig,
> it is still stuck at boot.

Ah, this is caused by a buggy version of "kasan: improve free meta
storage in Generic KASAN", which made its way into linux-next.
Reverting that patch should fix the issue. My patch that you bisected
to exposes the buggy behavior.

Thanks!

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CA%2BfCnZdp4%2B2u8a6mhj_SbdmfQ4dWsXBS8O2W3gygzkctekUivw%40mail.gm=
ail.com.
