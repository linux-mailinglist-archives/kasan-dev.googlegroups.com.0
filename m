Return-Path: <kasan-dev+bncBCCMH5WKTMGRB3GQ3OVQMGQE4XIT56A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103b.google.com (mail-pj1-x103b.google.com [IPv6:2607:f8b0:4864:20::103b])
	by mail.lfdr.de (Postfix) with ESMTPS id 691B080C6F7
	for <lists+kasan-dev@lfdr.de>; Mon, 11 Dec 2023 11:46:06 +0100 (CET)
Received: by mail-pj1-x103b.google.com with SMTP id 98e67ed59e1d1-286da86884asf4942239a91.2
        for <lists+kasan-dev@lfdr.de>; Mon, 11 Dec 2023 02:46:06 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1702291565; cv=pass;
        d=google.com; s=arc-20160816;
        b=apsN89djFcWryG3v5Pit50YaEJNbnWsVmdw3LP8zQXrjK6UyoRpz7tXncg6oBs/6Yn
         nJYqBg/42bK6ci0oMk+n5fqPsabAKJZAJqW/3jjnZ+MfGPyKWF8dEclL7Iou9C8yBl+X
         OlX9GSDeY9FoZuD4wkbuntb8LoEUSeE7cxl3JjBy08k6dyF2kKBzFm0PffRtCMd2Vrwh
         XSI/CxXeO6HbWQZc5otOVe4LMoTisEPSMo5DHPSVR99mg0NtwqAyh24srXDmhQ4WLWgH
         LNHfcrd1gbyCtjbXUeEdvFqst2ujviLPCyNWdPq2Q7rzwi0YqHx7LxYO9OflvN8AlR04
         28HQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=mdJwtsabKwNuTX2/qDsQ7rjaXRijD+sHQ/ZWAQhqLvY=;
        fh=kmKVJfn1Y9YZhlVPpqCDHuVVZsVgm/oqvGOUm8JK+fE=;
        b=w5i9hp6ZNv+syEYYVl80ZoitAIokZbO059Jmg4/suchPzW+NLuP9MglQZzjSPhEoen
         xmvENDa1u4WXwhvIFkYAxpS5gX45f+YGzIqte15MPlzY8FCuv6pQvAx0NNfDSGV1M3XK
         1S4h8koW/VND9dRathvaHS0RuefX+7G/FHL8h/axElqjFTL8hAwyvN+leAnxUU3oYc5Z
         OUNYUfmucRKGDy6n2DF3wczwBFZqdY0Ib3RQgOgQ12tKjadRKAzoQY1h7Y0/UA06+5nS
         iHddiR6H3SUfv7JAFhfshfOggFgi0xze3oD3cRoV9ONzR5Qjsps6Hy16lQCyyxOPd8bm
         JAqg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=P0w74eZx;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::72c as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1702291565; x=1702896365; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=mdJwtsabKwNuTX2/qDsQ7rjaXRijD+sHQ/ZWAQhqLvY=;
        b=sBbNzCIXqZBLTAjK/ChKN8pQGCUQvFaQpI/pjGOALVr5t0bSiu+CyVDOO0hkvwzTG3
         530ZHYOI+xNLWWQiNL7sp+BxGrVJQFpQxgiJtbnxLmfqZYq7fkzV43pvwVItAQso5EV/
         rK2MsbdmkivypYQOUd2x3/LZ9t+yvTTJ4C9OJ6uK2/BQH+0/Pz/LMbgHVTuE7yV/EoB9
         23Z9Mi+Xo8ft6KBGE97i/4VPrUsWWuHCIx/E67aLXU4skZpUP6Dyx6OkK+6W4vjYG8OR
         8mO39qG9gmHy2t5Ty29W/T9yR2tECXzxuawE8YLSYmhDfaUpNq0LuJrSur79559orthG
         HClA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1702291565; x=1702896365;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=mdJwtsabKwNuTX2/qDsQ7rjaXRijD+sHQ/ZWAQhqLvY=;
        b=u7sz9OZSaCoj07j29FrOeFmWn6zKPYoAJ/6YZAXoRX0jtpsUAO9PoX79hdXfCuYabv
         GW1RsTxblSidMOiBjJdB2unq8a51Mz0T4tcTzJbKYG5QkCWm8qyoArUa791ch6o/tKhX
         NdkfBBxkn8ZnKXjOwoZE8H5c+f3p9yVlrg4t30+qSzNjgSu7RPjgCXhvMZ8pJuvDj3Em
         n7Q7SUtDKn5rNKYUPkWXVZMQlrI1Uofg3hIAnsRCmh8Dsz2cJf2Wbk2Be8QCTxBKRQWB
         hSiWPrdIilbdm4qNWWh7mrFsq6Cyjl9KARqTm0x0bNcVHgjtnz9sK2Pl9Lto3dFqSLEl
         3GsQ==
X-Gm-Message-State: AOJu0Yy/Sv7AirnlaU6nPWGtlc4wgIQwGgH9XxjBneZUEjnVVxfuw4Ly
	q87TFO5VuYT+gcM0jqsWhf4=
X-Google-Smtp-Source: AGHT+IHctysxX8HMzbhy0NYlvmncV1OuMreK98s/JIBPgE+dWoKuowGqGMcFFAqP+5fugNxXocghXw==
X-Received: by 2002:a17:90b:1914:b0:286:6cc1:7817 with SMTP id mp20-20020a17090b191400b002866cc17817mr3177219pjb.90.1702291564893;
        Mon, 11 Dec 2023 02:46:04 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:c901:b0:286:692b:2de7 with SMTP id
 v1-20020a17090ac90100b00286692b2de7ls56675pjt.0.-pod-prod-08-us; Mon, 11 Dec
 2023 02:46:04 -0800 (PST)
X-Received: by 2002:a17:90a:a88f:b0:286:8b15:72a6 with SMTP id h15-20020a17090aa88f00b002868b1572a6mr3217936pjq.47.1702291563873;
        Mon, 11 Dec 2023 02:46:03 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1702291563; cv=none;
        d=google.com; s=arc-20160816;
        b=yf9hPXqhpyxC1rVPn5VdGZ1pgRFVTd6pXFpCkrrteKn3W4UhshkZD72Di5pueqSjt5
         db6u1vDL6BsV1IVkvG6ht2MCan9jdeMuZMZClN/sgqKpTtcwSBdbsuvk12n2VCl8yKqu
         KxFJtwih7JzX/GbN2Xnb+VTOxpJW600hBP0PNZvxFDnNG/o2wD1mx/l/KSM0Q489Ea1M
         L2UOA4AeOR0Hs8JxgD3Z7UiZ0AJqTpVbA67q2XUDkFF4DSECCXKRz6U0rAAQyuIdMTv6
         uwzx1WWyUSTMAd3edLhYig0GZ0up0yFAErr13NY9j/7SxQrljVEdbTG+2HoPqZ/IC0IO
         i/qg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=7oGkQuUWo91ye44C9IpsxZC6+sJmmo7+c+5R/ZoMYnk=;
        fh=kmKVJfn1Y9YZhlVPpqCDHuVVZsVgm/oqvGOUm8JK+fE=;
        b=Ms4w77Y6nHsMYP2wX7y78rgAUXRhhRSNaGmSt7DmWrreJXAHKtXn3npaSbILHrxx60
         ffTZoVSMfKo1i6gnS6pKHTGdokfSK+xCxHtFhPdFfhZ/F1MJdmJObzfrLrRFCVum5NDY
         zALzvM4LTBysXMluELKvYbXpwWARPK/Liyz/hIe84ogduG+R/8d8H+Cor0FV3UPL4QZh
         T1n8GQjrgzKmeI50Zkx3AU/l1S8dfSUwo4Fl26mItajj+/8aBZf2tN89e2lCB9hEnAQM
         4SA1zFd7jJuqqfqSyolwTFXmz8PrsN91CD6bU+9uhqa4imRSBMppA1UScnYPdgas4scW
         Rh0A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=P0w74eZx;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::72c as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x72c.google.com (mail-qk1-x72c.google.com. [2607:f8b0:4864:20::72c])
        by gmr-mx.google.com with ESMTPS id t13-20020a17090a5d8d00b00286f5f34e5esi367447pji.0.2023.12.11.02.46.03
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 11 Dec 2023 02:46:03 -0800 (PST)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::72c as permitted sender) client-ip=2607:f8b0:4864:20::72c;
Received: by mail-qk1-x72c.google.com with SMTP id af79cd13be357-77f48aef0a5so108096985a.2
        for <kasan-dev@googlegroups.com>; Mon, 11 Dec 2023 02:46:03 -0800 (PST)
X-Received: by 2002:a0c:fc48:0:b0:67a:a721:ec3f with SMTP id
 w8-20020a0cfc48000000b0067aa721ec3fmr2421212qvp.131.1702291562839; Mon, 11
 Dec 2023 02:46:02 -0800 (PST)
MIME-Version: 1.0
References: <20231121220155.1217090-1-iii@linux.ibm.com> <20231121220155.1217090-33-iii@linux.ibm.com>
 <CAG_fn=V5zMxGUQ=KmJh-ghTUHa-AZYn1CPTQNbf3x7Lu0w=HvA@mail.gmail.com> <13e3e073f6ed6aa48b39ec16add85baa677d17b4.camel@linux.ibm.com>
In-Reply-To: <13e3e073f6ed6aa48b39ec16add85baa677d17b4.camel@linux.ibm.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 11 Dec 2023 11:45:22 +0100
Message-ID: <CAG_fn=UX=8HrFzCSxmPgMn=H4cVmZ4GHE0Z+qZbpysOZwuH=aw@mail.gmail.com>
Subject: Re: [PATCH v2 32/33] s390: Implement the architecture-specific kmsan functions
To: Ilya Leoshkevich <iii@linux.ibm.com>
Cc: Alexander Gordeev <agordeev@linux.ibm.com>, Andrew Morton <akpm@linux-foundation.org>, 
	Christoph Lameter <cl@linux.com>, David Rientjes <rientjes@google.com>, Heiko Carstens <hca@linux.ibm.com>, 
	Joonsoo Kim <iamjoonsoo.kim@lge.com>, Marco Elver <elver@google.com>, 
	Masami Hiramatsu <mhiramat@kernel.org>, Pekka Enberg <penberg@kernel.org>, 
	Steven Rostedt <rostedt@goodmis.org>, Vasily Gorbik <gor@linux.ibm.com>, 
	Vlastimil Babka <vbabka@suse.cz>, Christian Borntraeger <borntraeger@linux.ibm.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Hyeonggon Yoo <42.hyeyoo@gmail.com>, kasan-dev@googlegroups.com, 
	linux-kernel@vger.kernel.org, linux-mm@kvack.org, linux-s390@vger.kernel.org, 
	linux-trace-kernel@vger.kernel.org, Mark Rutland <mark.rutland@arm.com>, 
	Roman Gushchin <roman.gushchin@linux.dev>, Sven Schnelle <svens@linux.ibm.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=P0w74eZx;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::72c as
 permitted sender) smtp.mailfrom=glider@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
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

> > Is there a possibility for infinite recursion here? E.g. can
> > `lowcore_ptr[raw_smp_processor_id()]` point somewhere in between
> > `(void *)&S390_lowcore` and `(void *)(&S390_lowcore + 1))`?
>
> No, it's allocated with __get_free_pages() or memblock_alloc_low().
> But since this question came up, I should probably add a check and
> a WARN_ON_ONCE() here.

Yes, please.


--=20
Alexander Potapenko
Software Engineer

Google Germany GmbH
Erika-Mann-Stra=C3=9Fe, 33
80636 M=C3=BCnchen

Gesch=C3=A4ftsf=C3=BChrer: Paul Manicle, Liana Sebastian
Registergericht und -nummer: Hamburg, HRB 86891
Sitz der Gesellschaft: Hamburg

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAG_fn%3DUX%3D8HrFzCSxmPgMn%3DH4cVmZ4GHE0Z%2BqZbpysOZwuH%3Daw%40m=
ail.gmail.com.
