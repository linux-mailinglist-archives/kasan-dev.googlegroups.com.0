Return-Path: <kasan-dev+bncBDW2JDUY5AORBZPT7WVAMGQEZKI5D4I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x339.google.com (mail-ot1-x339.google.com [IPv6:2607:f8b0:4864:20::339])
	by mail.lfdr.de (Postfix) with ESMTPS id C57177F63B0
	for <lists+kasan-dev@lfdr.de>; Thu, 23 Nov 2023 17:12:22 +0100 (CET)
Received: by mail-ot1-x339.google.com with SMTP id 46e09a7af769-6d63f6a5abcsf1067829a34.2
        for <lists+kasan-dev@lfdr.de>; Thu, 23 Nov 2023 08:12:22 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1700755941; cv=pass;
        d=google.com; s=arc-20160816;
        b=efj0GNpvpULnfW0MRD6c7WXJPhQrLjNq/ASWA1UIWsxI7HDGJs2wvZ+xE7Nr586O6H
         DjKQu9/f2UWkA8YzHVaorJIbScYFcC1UWTIfD0Z0WYHMdpkHWONUgrB2t+0GIXeC3k6K
         NrKdv6tCjye3etuPdilRFYdK5MQAfoCfhIojcotWGy1Y4IQ67mXUqauyk2zvT7GsUwLG
         H6URqhi1UoRJ0SzGABnl2hKZPvhMqVADlLoDj+gXnWNdEfRF/h37piMoBlBXrAUmkCli
         Xfcsvz3sSF8emjs8jh6QnebIZiNTUtgDmnIj7LbVIfPP4DRJ72WDeCxMoYhYjl+tXRIZ
         O1UA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=kUHRpp9PuRc+1ns7IFj35yO57eQxOJR8XaQaGls+xB0=;
        fh=zSh3cOr2bWV32wuLsS2CGXx0HFRiFXLMfTT1kX0bQEI=;
        b=sObk63dvDrBu5ic/vsudFz4xt76t+Uddto/D9VRBhoUzWZHe55Vwu93sBqjgz7aKMl
         cqhFmhzwx35LEZzl17lmjFfcN3auvuDcxMm5z/WsoFPE71KIBSm9a2huLn8HBrlboJqG
         939NbRNwNCF5ycSbBq7yL3twLWfc23uRzJqoFubHmYegsAZ3FiwtQp4D9HY5aZoxZtqu
         wz1ekOF1TMncTuGGHtG32MEiK50qprjy7IhjqQrRoSUTos3UOmAPYBqggnJFDw9fxr7T
         EAo6P1Z2jYt6VqImsRxhkuqGrd0etM3DXWcPiJLK1y4HscDxsYymn4HS43R3G/8O72rf
         ECsA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=cOW096Mv;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::f34 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1700755941; x=1701360741; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=kUHRpp9PuRc+1ns7IFj35yO57eQxOJR8XaQaGls+xB0=;
        b=p9loWhtZlHSk49nYhEc3FYvgHoC0LsOuC9/kDqrQAY+NWLb7zYH0TIWhDGHjhSn3IY
         hsXSB5b8hU5KfiSKXjSIi7xXhrDaCgkM0t7/uZOR5cCHOl6a8baxjoL3nzS6reTUFGtA
         Pj49e1vaCY2axg9HLvjGz8dmT9YHj9NnbdE38VK0XAQ27ehlNXdrMXHWjs+WVncLjUzs
         cYkslYm9zMEm1pCvNrjM86n9BvG9MpQBsaoALyqIRXPaDW8piWb+ADlyRsoBI9EA16a0
         U94CSShyV7QoFZC216YfHJE2inopGC5khX0g99I5TUJDYTEG00uZ+AulMGOT0atWPaRM
         jlmA==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1700755941; x=1701360741; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=kUHRpp9PuRc+1ns7IFj35yO57eQxOJR8XaQaGls+xB0=;
        b=W6GhiJ5bzA6yRh9Tdd/LyHsJHeC6YY9yKQ91ZB7u9F3waLdD9r5x8i5JjA/uRNCmWV
         sXuRJRuyoQCrvVg8VBP64NhY4y2Qdt2GCt8qPejbl3ts52HV58CHwDSe3Emgz4QaqfPg
         MX+EWuBrqXFtkAPfpQ6hsT2ov1fxzHhTT81ropIJCPWOHOqso62uizbdZeD4xc9ZMKmG
         0u+mYT79RLDpg24rhUJgZc4amMumPYLq8HEoV/o2pIoJpnHz5f4YgHBcAsMw55UHIxWr
         jcdkDhgwmfk9P29Yu5Yeok22b/EUxfxHTyP2BkZNvw06CY/Op/267/EgDV3pnSxrLaFC
         prNQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1700755941; x=1701360741;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=kUHRpp9PuRc+1ns7IFj35yO57eQxOJR8XaQaGls+xB0=;
        b=mlV20bv/G5M/+4mRz/HsnurxJAK3hreyerDixiszzK/F2D6XQ18wsFgB5gA3fe8gZh
         NknU++vtd2DFv8x+A2+yF8luGxzF1u1IkL3pEycny2EKUyfLxLDbNSTC8f4fbdX48Hvm
         KBBUcjvLj2swsbvc7qwwGBVuHFxxcLSy7sWA/InYnzGveJMQdOryn8ZZemg9l8CuaSl8
         eFN54psKLKopwMd37kvkpHKMOr9tsRPYvXKeQ8SnoYbWSZWbsMF4H+zEBfwQogmzQ3d2
         gp6PJqJQcpJ2A9WuSJyhp50gAiRV+Z7Uw3kX96b0bixqalmSILVwjSdIfcdQ7We6JQcL
         ZcbA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0Yxdgoz9rAOBd1XErvzI/+soOZFu4O5JNSTRfgApEQQPqS2ue0L3
	a3ibetwqmRdsPYaxTsbtf2A=
X-Google-Smtp-Source: AGHT+IFAsJ7akLI9ISaNrozFXHXajIxMjTkDf9bI34vxyxq0HbA0l5HXeLsXbuqvoEnCfM9VnWGW3w==
X-Received: by 2002:a05:6870:5cc4:b0:1f9:4d1c:9304 with SMTP id et4-20020a0568705cc400b001f94d1c9304mr7757105oab.14.1700755941116;
        Thu, 23 Nov 2023 08:12:21 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6871:20ca:b0:1c5:33df:eba7 with SMTP id
 rz10-20020a05687120ca00b001c533dfeba7ls1016331oab.1.-pod-prod-07-us; Thu, 23
 Nov 2023 08:12:20 -0800 (PST)
X-Received: by 2002:a05:6870:2a45:b0:1f5:cfb3:f586 with SMTP id jd5-20020a0568702a4500b001f5cfb3f586mr6945995oab.57.1700755940546;
        Thu, 23 Nov 2023 08:12:20 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1700755940; cv=none;
        d=google.com; s=arc-20160816;
        b=KQuIO/T9aYF6v3mtIbHnoJMtJSMiMJ1oTFyTrVMIkmfJ6F4k43M4qRNn0beu0ljABc
         sUG5DdThy2v7Jpxd/SlzRnfb8aXTj5lOuSPkRVnl9rg+lLRLLe1aohMSgeIxaHg5aZPN
         /8Tag4ISdnU71hq/L+aAOEFYEOOzCl3N2Hkjt8COUJZ2TjBg9Ih/jBHxYDm7cIM7PvA5
         9skaV+ceI8Ba04+xR/M/pCoC3As6X/QwBvLDb71+2Jw6be99G6YJVt1uGXF6BDuadNqT
         bsRnV4bpFUshE1/ehdM371qfIH1l6hfYBZxCaaahajSJM1h5HTaouw2DksJyu6nE37/g
         vLTQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=vGyQEtxcPZXDfK5MLunRkVEU0dG6NY5S9HKgUKbsr1Y=;
        fh=zSh3cOr2bWV32wuLsS2CGXx0HFRiFXLMfTT1kX0bQEI=;
        b=mtwlykqQXyU1rmKkVH5B5qGBIIIdZMugBf81pKzykoXwmMWw1Alr4+QUby9rspsNSh
         dt2mxk721cdzy9DKjRAMXlXTO6Dw9jt29CnwvVkPbjU4E+wvSpdx2rn1eT1un5Q/kJUF
         6IAcXrzvnmdYZ0HXtY0Ibjq1Sd89IElVM6Oa8VC56+Av4qr+v9eB+9rn7LLXwQmv6rgB
         X8VxDiLHB3W2ejsCVm7C3GlMw/9yS8KBvkqQhSdlWmmj7uYp0i/8ozptAYfr3ZPfZdKo
         Z7OlHYwBAZN7RnUpZcxjei/yylC+V/grsIb4DtzHp3onhNDWnDFTiST4hT+nkTh/wobr
         mT8Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=cOW096Mv;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::f34 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-qv1-xf34.google.com (mail-qv1-xf34.google.com. [2607:f8b0:4864:20::f34])
        by gmr-mx.google.com with ESMTPS id gu24-20020a056870ab1800b001f9ea588ca0si970oab.3.2023.11.23.08.12.20
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 23 Nov 2023 08:12:20 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::f34 as permitted sender) client-ip=2607:f8b0:4864:20::f34;
Received: by mail-qv1-xf34.google.com with SMTP id 6a1803df08f44-677a12f1362so6002936d6.1
        for <kasan-dev@googlegroups.com>; Thu, 23 Nov 2023 08:12:20 -0800 (PST)
X-Received: by 2002:a05:6214:21e2:b0:672:aecf:581a with SMTP id
 p2-20020a05621421e200b00672aecf581amr6478936qvj.47.1700755939932; Thu, 23 Nov
 2023 08:12:19 -0800 (PST)
MIME-Version: 1.0
References: <20231122231202.121277-1-andrey.konovalov@linux.dev> <ZV7whSufeIqslzzN@feng-clx>
In-Reply-To: <ZV7whSufeIqslzzN@feng-clx>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Thu, 23 Nov 2023 17:12:08 +0100
Message-ID: <CA+fCnZcAnZh7H901SZFsaU=-XrpUeeJwUeThMpduDd1-Wt0gsA@mail.gmail.com>
Subject: Re: [PATCH mm] slub, kasan: improve interaction of KASAN and
 slub_debug poisoning
To: Feng Tang <feng.tang@intel.com>
Cc: "andrey.konovalov@linux.dev" <andrey.konovalov@linux.dev>, Andrew Morton <akpm@linux-foundation.org>, 
	Marco Elver <elver@google.com>, Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Vlastimil Babka <vbabka@suse.cz>, "kasan-dev@googlegroups.com" <kasan-dev@googlegroups.com>, 
	Evgenii Stepanov <eugenis@google.com>, Oscar Salvador <osalvador@suse.de>, 
	Hyeonggon Yoo <42.hyeyoo@gmail.com>, "linux-mm@kvack.org" <linux-mm@kvack.org>, 
	"linux-kernel@vger.kernel.org" <linux-kernel@vger.kernel.org>, Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=cOW096Mv;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::f34
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

On Thu, Nov 23, 2023 at 7:35=E2=80=AFAM Feng Tang <feng.tang@intel.com> wro=
te:
>

Hi Feng,

> > --- a/mm/slub.c
> > +++ b/mm/slub.c
> > @@ -870,20 +870,20 @@ static inline void set_orig_size(struct kmem_cach=
e *s,
> >                               void *object, unsigned int orig_size)
> >  {
> >       void *p =3D kasan_reset_tag(object);
> > +     unsigned int kasan_meta_size;
> >
> >       if (!slub_debug_orig_size(s))
> >               return;
> >
> > -#ifdef CONFIG_KASAN_GENERIC
> >       /*
> > -      * KASAN could save its free meta data in object's data area at
> > -      * offset 0, if the size is larger than 'orig_size', it will
> > -      * overlap the data redzone in [orig_size+1, object_size], and
> > -      * the check should be skipped.
> > +      * KASAN can save its free meta data inside of the object at offs=
et 0.
> > +      * If this meta data size is larger than 'orig_size', it will ove=
rlap
> > +      * the data redzone in [orig_size+1, object_size]. Thus, we adjus=
t
> > +      * 'orig_size' to be as at least as big as KASAN's meta data.
> >        */
> > -     if (kasan_metadata_size(s, true) > orig_size)
> > -             orig_size =3D s->object_size;
> > -#endif
> > +     kasan_meta_size =3D kasan_metadata_size(s, true);
> > +     if (kasan_meta_size > orig_size)
> > +             orig_size =3D kasan_meta_size;
>
> 'orig_size' is to save the orignal request size for kmalloc object,
> and its main purpose is to detect the memory wastage of kmalloc
> objects, see commit 6edf2576a6cc "mm/slub: enable debugging memory
> wasting of kmalloc"
>
> Setting "orig_size =3D s->object_size" was to skip the wastage check
> and the redzone sanity check for this 'wasted space'.

Yes, I get that.

The point of my change was to allow slub_debug detecting overwrites in
the [kasan_meta_size, object_size) range when KASAN stores its free
meta in the [0, kasan_meta_size) range. If orig_size is set to
object_size, writes to that area will not be detected. I also thought
that using kasan_meta_size instead of object_size for orig_size might
give the reader better understanding of the memory layout.

> So it's better not to set 'kasan_meta_size' to orig_size.

I don't have a strong preference here: slub_debug and KASAN are not
really meant to be used together anyway. So if you prefer, I can
revert this change and keep using object_size as before.

> And from the below code, IIUC, the orig_size is not used in fixing
> the boot problem found by Hyeonggon?

No, this is a just a partially-related clean up. It just seemed
natural to include it into the fix, as it also touches the code around
a kasan_metadata_size call.

Thanks!

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CA%2BfCnZcAnZh7H901SZFsaU%3D-XrpUeeJwUeThMpduDd1-Wt0gsA%40mail.gm=
ail.com.
