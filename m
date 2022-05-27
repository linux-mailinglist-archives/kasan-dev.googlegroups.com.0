Return-Path: <kasan-dev+bncBD2NJ5WGSUOBB6P4YGKAMGQEDC2NRIY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x238.google.com (mail-lj1-x238.google.com [IPv6:2a00:1450:4864:20::238])
	by mail.lfdr.de (Postfix) with ESMTPS id DCE98535A6C
	for <lists+kasan-dev@lfdr.de>; Fri, 27 May 2022 09:32:10 +0200 (CEST)
Received: by mail-lj1-x238.google.com with SMTP id f10-20020a2e9e8a000000b00250925fec6asf1079585ljk.20
        for <lists+kasan-dev@lfdr.de>; Fri, 27 May 2022 00:32:10 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1653636730; cv=pass;
        d=google.com; s=arc-20160816;
        b=qmHKpWUsQG8t8C77nd8/FOs2QJshMawhHBiEm4NrjgDShIS+5Vd05Q0w5WWeS0oSpu
         tte/dRULF6o1WL/2+B4zoEhOpwUcdqnI9PzQtqdQ9wKRjxCfXHGCrk/UfHkPVqDdjqvF
         vAhlx+NqiwLb0WdjFXagOgeYDnOMxpOC60B6DPKiecxkPaEBgPFwsEMlberp0ptcp4xz
         yTMrNEJnd75XCqmts8trHqEI1yCCT5LTKMIfISNP7iWgkCLDH1gcH2/j2ocUnELc/dJT
         9OfjLhcY9PoAiNn9jUdGP6K7C35CeyKeSjN35qcMOYHLXrtQsPIdjuIkvp+8ladLLQdD
         7WmA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:user-agent:references
         :in-reply-to:date:cc:to:from:subject:message-id:sender
         :dkim-signature;
        bh=k/m8weXSDNwY8mUvM8n+51KNwzHMp3FC9kcN3sKK7ng=;
        b=EsEVU7Q5M6iBqX4JIaZeL9oznoSeDeOcYN96pZ8nNiOyPiCyVQGlv7cY4Flsd0eECa
         vQG3BA+GXZh86G4uN4KaV87sSGqAcytb272W5QZOuCRmylT36l6PZbpBRwvbn49BMLBy
         EAF+Fbngd4WiA6w2yCfLXsJItP5+v0+pwc1VyeiOehEZff/kOVZdsDpRpPUu3oLb4DWO
         /XEWW+mrNjDergHUReqCirXTO/8+EA+gIdJlqjK2fgAGP+1D/dBi5iwmPkfGR/xw5w0Y
         Jh892w62lAdNsTyQkqGnJfznHE8Vd9n+vQu6ZgTxvKezgl4nEteWHE45EgwbFxLiP+nG
         e6Ow==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@sipsolutions.net header.s=mail header.b=tS0RexmX;
       spf=pass (google.com: domain of johannes@sipsolutions.net designates 2a01:4f8:191:4433::2 as permitted sender) smtp.mailfrom=johannes@sipsolutions.net;
       dmarc=pass (p=NONE sp=REJECT dis=NONE) header.from=sipsolutions.net
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:message-id:subject:from:to:cc:date:in-reply-to:references
         :user-agent:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=k/m8weXSDNwY8mUvM8n+51KNwzHMp3FC9kcN3sKK7ng=;
        b=Qgp7lheFpDiMzTZWpR6zvp266T0Onl4qeilTvaivavVoC8AyuaFqzHgqEbtbTCWnsT
         pImuUf1f7XjCu8Ivd7YRFcor+VdYgfyi01bc7YJZ3gcK+wWZc2XeXvwjn7WoJO11PF1/
         AKs44l5IHi+JNB72PFR/+zboEbn2N0Rib5S+LT4Qf50KBqR71cPM1nI5f8flB8qA9dfl
         VfNROOBK5MBjB0skBEDjZQI0E2hfy1fezR+yHUmCdAm7IeKtXQnkkY4KrPmThrX9Ho4g
         xwnnfjqdP/FIMIatz9JdRdz87O/iZ0P1Hb8naFwFUpb80AJ/cZ2Y92r5lLAzgq/wBPGx
         fzVA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:message-id:subject:from:to:cc:date
         :in-reply-to:references:user-agent:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=k/m8weXSDNwY8mUvM8n+51KNwzHMp3FC9kcN3sKK7ng=;
        b=EAxhpXewXP+ZtnjWTSVSqfRDarNp7zDqa3CfT7+pgzep96ID02eBpowAc0uGbZVlOY
         TadpIwtO5khdMgRKIPr2s2h6E76caZUYIcoukz/leZ5GfI8ANtJa3CuN8NrnJtZCLsjs
         80E/ckWjig51ezYwwcl+FRn2AzHvqjwHjMDOsYozMQcplwbsgo7TNsWSJTxmxmsxkmhf
         HKNitdnwGbDQXR4KL3yLRCOuBU+fMbuMD4Yu4E9NucbBqQPRw5ATYXHex7pN8qrN9G3n
         snRpGQtK+24x6URE/HZq0LFsM0O8IDhf0BeHiZI43SIkFzIe8uEzwAGfN6n15PjAyE+i
         9REw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533VZ6aiADgd9REKuBo6AKPvDQWbX0CQAFh8Mz8jofwIUa/lgeVR
	o88UIf4qGgTRpjwwFElTuR8=
X-Google-Smtp-Source: ABdhPJw3b+Yru2ROY/0zN9w2zhuT2+N/u5mDc9ijswloKayQqxDxmiaoEjbZHdw2gDX/ZEz7LpVcqw==
X-Received: by 2002:a05:6512:1305:b0:478:67dc:1a with SMTP id x5-20020a056512130500b0047867dc001amr18892031lfu.559.1653636729993;
        Fri, 27 May 2022 00:32:09 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:3f16:b0:449:f5bf:6f6a with SMTP id
 y22-20020a0565123f1600b00449f5bf6f6als537682lfa.2.gmail; Fri, 27 May 2022
 00:32:08 -0700 (PDT)
X-Received: by 2002:a05:6512:3d8b:b0:478:5cb7:8e5b with SMTP id k11-20020a0565123d8b00b004785cb78e5bmr21244556lfv.433.1653636728841;
        Fri, 27 May 2022 00:32:08 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1653636728; cv=none;
        d=google.com; s=arc-20160816;
        b=p25JaT2qNv4plBv2dtY8gsw4PAjgUsyM+8ZYdeoknKAieN5cWV6/kysS4pV+ntdbb1
         lNf/hUco5HYEQiS1JEqhdWeIOjLBbP6GiA2JQ/CjH1HqC+4yO/Z2tOZTOvZlset4Gh8Y
         OzVbJs0VTLMOz7B1QEK5IRqQmICBtEOIrQYuecnqw6aPNGg7LBPAmLjB5ohZMPOOEVNL
         CdwzwhoN66cBQuCdtka13Xp/l1U0F2jXzqX0H3mCKmBpy8YqBUcI8XmhD2AjF2bfC5TN
         EhyuqiYdzUfcWk4Xjcb0KHfBwjuQ9aer0HB9gHKM6aSXmSJ/upKxbt7V8iqB5h0qc0kF
         Vh+w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:user-agent:content-transfer-encoding:references
         :in-reply-to:date:cc:to:from:subject:message-id:dkim-signature;
        bh=7L1UvtWzSeI1RAxfnE/3HtRDKWRdqRZ2oSzwia86H/U=;
        b=SAQrnHLfQ41aQaZ5DFkG4IKeIYx1c8rziVLTqt7X5qCG/r+4gTebiGGEC9x0vPMXlf
         9DalD71vHsRuAgbK15y4wxxMRD2vvKJFUGmQTdON87+2WX4muyDtVOZvYN2oxsiP2wwi
         NGzVrhtt42Bl01uBve/CqW5EhaUwcMiZxI6iphNMr4O+svivTcnCKaAdy50FSUZKZk8i
         6qNGjFJQlf9w4Q0eIRYqzO2+BKal5160wGb60XReZFMEEc2YnqbP5jxSWF2+R0bl+aT+
         Fpeqn3IdE9XL8qK99uxKVYC2gv9awwX81PfeQO2BmiPh8BiTQTSCAWCxzuGxZuiuqRQk
         hFWg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@sipsolutions.net header.s=mail header.b=tS0RexmX;
       spf=pass (google.com: domain of johannes@sipsolutions.net designates 2a01:4f8:191:4433::2 as permitted sender) smtp.mailfrom=johannes@sipsolutions.net;
       dmarc=pass (p=NONE sp=REJECT dis=NONE) header.from=sipsolutions.net
Received: from sipsolutions.net (s3.sipsolutions.net. [2a01:4f8:191:4433::2])
        by gmr-mx.google.com with ESMTPS id z16-20020a056512371000b0047866dddb47si173139lfr.2.2022.05.27.00.32.08
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 27 May 2022 00:32:08 -0700 (PDT)
Received-SPF: pass (google.com: domain of johannes@sipsolutions.net designates 2a01:4f8:191:4433::2 as permitted sender) client-ip=2a01:4f8:191:4433::2;
Received: by sipsolutions.net with esmtpsa (TLS1.3:ECDHE_X25519__RSA_PSS_RSAE_SHA256__AES_256_GCM:256)
	(Exim 4.95)
	(envelope-from <johannes@sipsolutions.net>)
	id 1nuUS4-005xX2-LH;
	Fri, 27 May 2022 09:32:04 +0200
Message-ID: <1f0e79c925f79fba884ec905cf55a3eb7b602d48.camel@sipsolutions.net>
Subject: Re: [RFC PATCH v3] UML: add support for KASAN under x86_64
From: Johannes Berg <johannes@sipsolutions.net>
To: Dmitry Vyukov <dvyukov@google.com>, David Gow <davidgow@google.com>
Cc: Vincent Whitchurch <vincent.whitchurch@axis.com>, Patricia Alfonso
 <trishalfonso@google.com>, Jeff Dike <jdike@addtoit.com>, Richard
 Weinberger <richard@nod.at>, anton.ivanov@cambridgegreys.com, Brendan
 Higgins <brendanhiggins@google.com>, kasan-dev
 <kasan-dev@googlegroups.com>,  linux-um@lists.infradead.org, LKML
 <linux-kernel@vger.kernel.org>, Daniel Latypov <dlatypov@google.com>
Date: Fri, 27 May 2022 09:32:03 +0200
In-Reply-To: <CACT4Y+a191xbPi_0w6imTAYHDeAoudrxbWiuERBOk41e5q_K_Q@mail.gmail.com>
References: <20220525111756.GA15955@axis.com>
	 <20220526010111.755166-1-davidgow@google.com>
	 <CACT4Y+a191xbPi_0w6imTAYHDeAoudrxbWiuERBOk41e5q_K_Q@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"
User-Agent: Evolution 3.44.1 (3.44.1-1.fc36)
MIME-Version: 1.0
X-malware-bazaar: not-scanned
X-Original-Sender: johannes@sipsolutions.net
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@sipsolutions.net header.s=mail header.b=tS0RexmX;       spf=pass
 (google.com: domain of johannes@sipsolutions.net designates
 2a01:4f8:191:4433::2 as permitted sender) smtp.mailfrom=johannes@sipsolutions.net;
       dmarc=pass (p=NONE sp=REJECT dis=NONE) header.from=sipsolutions.net
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

On Fri, 2022-05-27 at 07:31 +0200, Dmitry Vyukov wrote:
> > - This doesn't seem to work when CONFIG_STATIC_LINK is enabled (because
> >   libc crt0 code calls memory functions, which expect the shadow memory
> >   to already exist, due to multiple symbols being resolved.
> >   - I think we should just make this depend on dynamic UML.
> >   - For that matter, I think static UML is actually broken at the
> >     moment. I'll send a patch out tomorrow.
> 
> I don't know how important the static build is for UML.

Depends who you ask, I guess.

IMHO just making KASAN depend on !STATIC_LINK is fine, until somebody
actually wants to do what you describe:

> Generally I prefer to build things statically b/c e.g. if a testing
> system builds on one machine but runs tests on another, dynamic link
> may be a problem. Or, say, if a testing system provides binary
> artifacts, and then nobody can run it locally.
> 
> One potential way to fix it is to require outline KASAN
> instrumentation for static build and then make kasan_arch_is_ready()
> return false until the shadow is mapped. I see kasan_arch_is_ready()
> is checked at the beginning of all KASAN runtime entry points.
> But it would be nice if the dynamic build also supports inline and
> does not add kasan_arch_is_ready() check overhead.

which sounds fine too, but ... trade-offs.

> > +       if (IS_ENABLED(CONFIG_UML)) {
> > +               __memset(kasan_mem_to_shadow((void *)addr), KASAN_VMALLOC_INVALID, shadow_end - shadow_start);
> 
> "kasan_mem_to_shadow((void *)addr)" can be replaced with shadow_start.

and then the memset line isn't so long anymore :)

> 
> 
> > +               return 0;
> > +       }
> > +
> > +       shadow_start = ALIGN_DOWN(shadow_start, PAGE_SIZE);
> >         shadow_end = ALIGN(shadow_end, PAGE_SIZE);
> 
> There is no new fancy PAGE_ALIGN macro for this. And I've seen people

s/no/now the/ I guess, but it's also existing code.

johannes

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/1f0e79c925f79fba884ec905cf55a3eb7b602d48.camel%40sipsolutions.net.
