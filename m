Return-Path: <kasan-dev+bncBDZIFAMNOMIOL67Y5QCRUBEIINUO6@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13c.google.com (mail-lf1-x13c.google.com [IPv6:2a00:1450:4864:20::13c])
	by mail.lfdr.de (Postfix) with ESMTPS id 563FFD1964
	for <lists+kasan-dev@lfdr.de>; Wed,  9 Oct 2019 22:07:02 +0200 (CEST)
Received: by mail-lf1-x13c.google.com with SMTP id f3sf832300lfa.16
        for <lists+kasan-dev@lfdr.de>; Wed, 09 Oct 2019 13:07:02 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1570651621; cv=pass;
        d=google.com; s=arc-20160816;
        b=i7YNPwkr/7sSAphTwmjXqiF0Rwzl2f2XMXGm1MDZ6dgkmHrS4I3d8BvuC0RlUxoMeZ
         yN7SgwBlZeV98LfdPiXk638R/WQF7xawSWlh1tr3M1tRgZX7xf6RhNXRn0SUo4vfxZ1M
         BctPSoSqnuq+4rSVF8nmz62qEN+zO1NdwL99BbVOzP7zCWWgooouzU3nuNk5oQ/KpA+b
         JC9VP2LFHmole+O3gi4NaC7CHVBjKvOi/wEITBW9BPg7SKfpmvd5g4ikQ24afzmBu8em
         CY6W/Q731OqejZ0B7BigHgbdaJQ+CvVeXjVI0+bAhgZrurayNeYAaNDgZsiMPsWwgn00
         9GJw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :mime-version:user-agent:date:message-id:autocrypt:from:references
         :cc:to:subject:sender:dkim-signature;
        bh=wCyJMtW2gSD7g7A/YESU2ZXtl9D/qKbp1OxbndoTkMc=;
        b=WSKbKFvx2+6JE/+HjPl7dM9N5fzum3nmqGfiq5L7DzG7D3ihBvZRYhfUE1bc86Ptyk
         w2i1JNGMvQ4qmOc9LAK+ESI7FWkpO+H09T6evosAlpugkIA4xdAb6yUtRpaJYbNo7wJg
         UCwUBVrYn8ylTWmTdT/hUhjCsL3OOmHZKzduUCnaDcg+bj0afmavrgfdGF9hLR+NyQiR
         S8GXiIo2MGbmQiTeMepRwxhJo2Vudv4GAkyh1t4ff90kfoXpcaMh4t/geKm7o+FYca66
         d6b36CwIn6pPBPsRIsClD5+A9c/dz3DuQ3GALBoo5mNhF8bNlNvx9Uv2aqtWGn7oKWGU
         p+Bw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@web.de header.s=dbaedf251592 header.b=Sn8u1WRd;
       spf=pass (google.com: domain of markus.elfring@web.de designates 217.72.192.78 as permitted sender) smtp.mailfrom=Markus.Elfring@web.de
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:autocrypt:message-id:date
         :user-agent:mime-version:in-reply-to:content-language
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=wCyJMtW2gSD7g7A/YESU2ZXtl9D/qKbp1OxbndoTkMc=;
        b=CH5a6Uiot3cfQSc8+aj6CKoeQy5Hf565s4oSTO8UJxDcawrqRECeDrVR/ty0tssqxF
         YzN+3P9kbuj7DGx1rMP2EQheiTqDR4PxYlq8CONODQeGCqGuYfCl+tK5n4TcQmLXY0sP
         iwSqRKkYHmU/VdAtKxhz0BtsRD8ywgWIxVoDkAOSRZT+k90EvMFoZA6CNPfVL598kRKX
         yIoEQLRK0p2U8qjpIfqyAY2Xr/Tzu9z2b1NAV9AcP4fzs4pazVkATLgD+yqNdXpsHMBW
         XWb02PKyLdPMQ2IzI9RpwZA0YtedRTyjKA3iteu78UHbUKrFBngX70U4ggVZdgdMn3nZ
         wPLw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:autocrypt
         :message-id:date:user-agent:mime-version:in-reply-to
         :content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=wCyJMtW2gSD7g7A/YESU2ZXtl9D/qKbp1OxbndoTkMc=;
        b=PkXf5QDtNWCuEg8OQDL9T79IIFrFseiJ2c9a4iZ/FaaLsuxO0dSTd6BxE4sxD8j6OZ
         HYSJvxAYEX4An4rAw0TaFydJI0PbbjH1patHLlYlYaOaiWJ2jANxXcVhEf8foSqzLDXZ
         t1YE0FVyoz8Vhi9OOCC3Qwyuxa9n8JmtxZ35WKJrO2XElquq2Pfg66CD2LZ/BlItVEtr
         PHnpwuTPQ44dR/0YGNmGptv8h2VESfQ0w81rhsKqAxgGKbkxokFs/7BddGUpoBhwdNlD
         GDlAk8EYAU+YoASYPPQkyewWs6yRHD0uhDaGb+XNnvGghDkAjGIGqWZunOsZ94XpZjxU
         IhJA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAX39x5gcUUcelIbFhJV0ajess0GLPg0XxrvQJD79jLrO6R8n5Xi
	lAG4P4X9AUaZpm2H5fS+fc4=
X-Google-Smtp-Source: APXvYqwiFAmCPYBmBsXIOlsTlsNoZ9vI/6j/MmMP49cQg2iE6It6wmSTm/yuRhOB7mKowy3VYRA/jw==
X-Received: by 2002:a2e:1214:: with SMTP id t20mr3429817lje.191.1570651621877;
        Wed, 09 Oct 2019 13:07:01 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:651c:1043:: with SMTP id x3ls195444ljm.14.gmail; Wed, 09
 Oct 2019 13:07:01 -0700 (PDT)
X-Received: by 2002:a2e:b17b:: with SMTP id a27mr3487011ljm.243.1570651621166;
        Wed, 09 Oct 2019 13:07:01 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1570651621; cv=none;
        d=google.com; s=arc-20160816;
        b=C3aaoo42OiKuJ5blzoKgkJEbK7AtchfPjYbWzZgOuEf8gQPFLDCTh8Sw493ghbA1yx
         E9b/Mrn3fqWGvmV0JXvsLqaRZkVXAuQvn8LVAaimPBNtn1EMJjtLUlQwtxZySFL7aErI
         EfDWRc60po8c8ZbN5cIor1RJ+UvUuBR2tquleDTpG+f4L/+tUZeOqpSbPchsgG3H58al
         pcpB8FDPqUfT11VgiRp7ZSpBu15FHgUIybRQkaEAE8wYCAJDIlpOTqlNHUcyV2WjrsPU
         162Fh+PG8ITaKdFh+VMdnLgQQBBF87HF8JwVtko4mHBjL1Us6hm6xYAVlqXFSunBEVGi
         TkJg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-language:in-reply-to:mime-version:user-agent:date
         :message-id:autocrypt:from:references:cc:to:subject:dkim-signature;
        bh=SomjzGLYWNmKI5LdMK1dUZRhc+1Ld9HiIOpQO2lDapo=;
        b=Gr5Xzk5oWDCrZdxWSI2lVLMnizFOqgb5v5QDS/4IKAmIBayLaN6A5Fh6ThP6n0gto3
         QxHXVMaHh9UiyXsg3yv7n9awQXIFCfRD1U8q1j0GXB6yI3AsWTrAYz++4MWtO+Zd6PqN
         xP6hdosJRYyFAkWQQIkaTDcIvMsxt9Qh/JWMv+4btJNM6YpwW1yHbHdcH9ngchSk82Cw
         VpuYGbzcZg1uL+M+Wd+d+DPZAZHPiYbYokX14CPdF/rfmJGC83MoV5JWcYJ+Otxo1F13
         4vP7ewPvJPeecjPFuMe+QihQiyO9oISQ4mgNzVi2IickFcmm5165URyhsvZue9Z33/2s
         0WIg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@web.de header.s=dbaedf251592 header.b=Sn8u1WRd;
       spf=pass (google.com: domain of markus.elfring@web.de designates 217.72.192.78 as permitted sender) smtp.mailfrom=Markus.Elfring@web.de
Received: from mout.web.de (mout.web.de. [217.72.192.78])
        by gmr-mx.google.com with ESMTPS id z4si239274lfe.4.2019.10.09.13.07.01
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 09 Oct 2019 13:07:01 -0700 (PDT)
Received-SPF: pass (google.com: domain of markus.elfring@web.de designates 217.72.192.78 as permitted sender) client-ip=217.72.192.78;
X-UI-Sender-Class: c548c8c5-30a9-4db5-a2e7-cb6cb037b8f9
Received: from [192.168.1.2] ([93.132.177.35]) by smtp.web.de (mrweb103
 [213.165.67.124]) with ESMTPSA (Nemesis) id 0M4ZXs-1htAbD0ksG-00yhZA; Wed, 09
 Oct 2019 22:06:55 +0200
Subject: Re: string.h: Mark 34 functions with __must_check
To: Steven Rostedt <rostedt@goodmis.org>, kernel-janitors@vger.kernel.org,
 kasan-dev@googlegroups.com
Cc: Alexander Shishkin <alexander.shishkin@linux.intel.com>,
 Andrew Morton <akpm@linux-foundation.org>,
 Andy Shevchenko <andriy.shevchenko@linux.intel.com>,
 Joe Perches <joe@perches.com>, Kees Cook <keescook@chromium.org>,
 Nick Desaulniers <ndesaulniers@google.com>,
 LKML <linux-kernel@vger.kernel.org>,
 Andrey Ryabinin <aryabinin@virtuozzo.com>,
 Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>
References: <75f70e5e-9ece-d6d1-a2c5-2f3ad79b9ccb@web.de>
 <20191009110943.7ff3a08a@gandalf.local.home>
From: Markus Elfring <Markus.Elfring@web.de>
Autocrypt: addr=Markus.Elfring@web.de; prefer-encrypt=mutual; keydata=
 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 FEE=
Message-ID: <ce96b27e-5f7b-fca7-26ae-13729e886d46@web.de>
Date: Wed, 9 Oct 2019 22:06:52 +0200
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101
 Thunderbird/68.1.1
MIME-Version: 1.0
In-Reply-To: <20191009110943.7ff3a08a@gandalf.local.home>
Content-Type: text/plain; charset="UTF-8"
Content-Language: en-US
X-Provags-ID: V03:K1:UuGZv/Rj7bp1Zs67fNW7zUExO1QJjGbL2a9NMe7fh5N4ZcXmGrt
 A5oyZlnGoa2hWqsgGGLAsCG6/ojI0ilIKHV1tuZTEXcrUBYhIbXeM9M+BqZoXMAXfKmqFrq
 +1EDWNPXIXmQiYjeNK25KRC1MSx7n74SriuD1m2jqaHRecQkgppVLgoDJRFeTDrZ7Gf57Qc
 3CDkGVRzVzBvwmLyrPu7g==
X-Spam-Flag: NO
X-UI-Out-Filterresults: notjunk:1;V03:K0:QcbYFq7GTgk=:QKlX5Ux0TnOjhgdpdlSLWF
 4yfCSyyJXqDhg05ZUXFZI46xLTxqLLtEo3kNq5SDnR7Mu3+8p0VR408o/uyNgDiOI+f6QlNTz
 wQO+GtTOvJyvmzhZkbcMOgO8rt3X9aVJT8hk0ws97jXBRDVfudqBog2W6FUEtPtTS0zEqj8EH
 /UGCnKEx4yvar58N2qlBPtUxuuiPOmv8skQR7P9ESLoAiPe0PjCLkQQAFrqR9s6B2xsJSeUrl
 ejE6q9vYlp/5VKrXwXvRzyem9Q7UaH4KrJs6l52tyXb+qy2HIXEuWNxLD6X4FXpc+IHzQHn/3
 iev4l9TS31gOhmp5fBJbIpcSOZJ7C3LrrinkqjVaK0dMOgp2fD6X87d0Aa2XSYC98qL/DHaAe
 H5rmvw9KrrpxEnXvD3wfRTbrVBFsLKKr0cgNoOnJ0+uk20ldGnmXNo6Xh4i+/E71f6c+hSPFq
 ibXxnj9q5p2rTzVQr0h1dsQZUumjW0ZGyI8MfxZpa1M8AA0QPtnI8bhlv2hyqLpcmZwA0C29/
 rsiffqyAEtMJlR3LrcIw1iwc7HgZH5XzW1A+N7L6egyaW1s2KpwVwJSAKnpZbQHOP/Dbugt/4
 xE+6d1Wm1eNgmRqUN5Pm/U3p3kkPbUrvpjgL65Z5KoCgqoMPHLfo6Z/YGtNLU1XR9K2qO3N4D
 BFEZiBsXHQXUjTQgteUs5NP6Mwwdj3O1RfCTCIGic1lTZj9uPQay3QWl680i3A8D1LkMmQP6J
 G2J9/O52seLF+l25z1uNHULOe98GF+uk2b9v6bHr0AqEsj3jJtgCcMY9TZ8eVfV6uNpPDlLuQ
 Fy9tUdxIxmEAkh69GlXZG/i9qJFzt7WVgsd3R91rhC7O0FmQbF3S5RIbHWGwVRrnhkr9N2wrQ
 Q7G1J6vzW7PGFv1Tial3e1bUUAy87/Jo/MgY2bi9PYuyNcVQCi/GiBmLUx582gbvLbIRXd1e+
 GSE3N0vL4qos02Wu3M+IFvlJCXAeTbWHvbC1Q14ibt5VWiYI52YTk7SHPFTUlTNqTvWgk+/O0
 IsO6M2gl96B9GI148viUpRNfsmUgrxXp+ooLJeo2YTlN8Xw4Tl2TrGxmsy9JTObQ6LSf15j7A
 2Y1uO8+s6yzBxgGkuTHOtiy7CeWFPBxcfO7Ts2dWEIpiJLbrZdlLNgvqdcKLUeW4vdoHU6b6y
 zSQTMQpKuCW/lApdUVnVSgM7HxGTKLiJV5syMmazHjT65de4QfGmm72Z/ucI/cYEmIMibW6Xe
 2vEeQsgqmWmE+DWY2SYjNofWbog/rjVOSb2Jokd8d8IFmWNowiQO5+obCmmo=
X-Original-Sender: Markus.Elfring@web.de
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@web.de header.s=dbaedf251592 header.b=Sn8u1WRd;       spf=pass
 (google.com: domain of markus.elfring@web.de designates 217.72.192.78 as
 permitted sender) smtp.mailfrom=Markus.Elfring@web.de
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

> I'm curious. How many warnings showed up when you applied this patch?

I suggest to take another look at six places in a specific source file
(for example).
https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/lib/test_kasan.c?id=b92a953cb7f727c42a15ac2ea59bf3cf9c39370d#n595
https://elixir.bootlin.com/linux/v5.4-rc2/source/lib/test_kasan.c#L595

Regards,
Markus

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/ce96b27e-5f7b-fca7-26ae-13729e886d46%40web.de.
