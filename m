Return-Path: <kasan-dev+bncBC6LHPWNU4DBBE5Q4OMAMGQEB273UQI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43a.google.com (mail-pf1-x43a.google.com [IPv6:2607:f8b0:4864:20::43a])
	by mail.lfdr.de (Postfix) with ESMTPS id B14275B0BAB
	for <lists+kasan-dev@lfdr.de>; Wed,  7 Sep 2022 19:42:45 +0200 (CEST)
Received: by mail-pf1-x43a.google.com with SMTP id dc10-20020a056a0035ca00b0053870674be9sf7893072pfb.12
        for <lists+kasan-dev@lfdr.de>; Wed, 07 Sep 2022 10:42:45 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1662572564; cv=pass;
        d=google.com; s=arc-20160816;
        b=DFPKAvWGztH3adhFeAGEBav7C5zRbkrz7H7/U3A5wVCJuDzy9HUqH+Wz4z+zFo8xa6
         ptOoQRyG0o4TLAEdMU7dXtz/nHFVDQT+jISjUrgVBUHW3C6P2a2LlIQkgasjIuIdQlOu
         IGXDbcI+Rz0HuC7QHYTyzyv9nCNVGwrIKT1+gnbuG9vczTw6Ug2ELDeg47fPsJJsuTp2
         Z9LEwbpiI+kga+484L8JSRbQXe5MZS7vYnqgM4Lrlopvebe0Y70mSzg2SmLARQhfryJx
         EJ7OFghzQxotZsHEVY3l/lRbPdJCsORweM1JmKOp77W3OGOkxoySwK+AhH5x2dBNGrKw
         t8cA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date
         :feedback-id:sender:dkim-signature:dkim-signature;
        bh=kOrAmzNniU0YMSnSqeFp9QoMr+5tlqk6QgkXyUq8V2A=;
        b=u3RKREGBYQSzWaO3tGCMhsHFykZMZwEgWjvqfA/Nip5GWERZ7+Kmvm3MygwZbj4ojm
         f/hj6loTapqXq9SyxFgF3QB21360C64Na5gI7fLKznPOHifCRjHNfeoVu2zd8u9xNJ6a
         aQSee4+fkKoOdTuifYMF62gEFUBwtF8dgXiVZkMaOIbgh20T3cp88OM91mW2I2OSAIDH
         /mkiSJZ78Su9aSVPaGfNLFqIAKDoje+qIyOOhwlo8WVzD0wKaCuRLjcTIFBMMg3J9BIq
         3wvFWkC6u/8POStJ4PX5O5/FPXbipYFVzc78esLnLBcoFJa87bzkN4VK804aeYqGb29u
         d2Ag==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=gRbEXFRf;
       spf=pass (google.com: domain of boqun.feng@gmail.com designates 2607:f8b0:4864:20::72a as permitted sender) smtp.mailfrom=boqun.feng@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:feedback-id:sender
         :from:to:cc:subject:date;
        bh=kOrAmzNniU0YMSnSqeFp9QoMr+5tlqk6QgkXyUq8V2A=;
        b=hmvz6bkibHEJLyWd0VaggT25vS0HbkD0BKJy8+9l1RNDw0sZA+/rZhCS+qteDdykrZ
         lNgwCMWPZqajBkNxdtg557Alg6E8N3upoi2/GfWKVjWNXq9WfidIk0kadMWMkM9UR/tR
         d9PVWfxQK1J1/ohrm9Hy0lP1Sr9GO688OE7FseltZKZByIfG8Vk6egFJ+7DNtRnCib8l
         Wb6YJLuYLLxwY7KujHsKUGk5N4oD49hosSiOk3apwMguLHvQlE/z43OX2R8CLqQ3e+gl
         UfZtAdtCiRg549p5q10SUXFmC1Ik7C/K+nv0nySLSPzPFX6Vjt3dybxjenIeoj7ol0Y/
         X7Qw==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:feedback-id:from:to
         :cc:subject:date;
        bh=kOrAmzNniU0YMSnSqeFp9QoMr+5tlqk6QgkXyUq8V2A=;
        b=BVqOi45LjACZU+/KO6tnF/snTynlEo1O3IJ8uMXzsXGEzhU9e16z7X/VFOeFya7Qpk
         /1klXF4ZfOs1jyq8D0TN24LUxm8X6R3tS31ELfUbP3sD+jAMHAzeth93S+bqyP9aATIh
         aS8NIfI50Ig4U95AHop2TwGp11NVSPiKDcioBWwFFveor/GOpXWIQz1+BcIgTAwYcFFz
         sE6QcVha0w/PRyf1q3f/IPPJnwcXFkamuHOJY9t4/5v46/tH5IMnYJjBTXmItxk2r4in
         +2bx2JdOXelYF89xaE5LZkaQ+3PJacZpD5LKcRE1OK0iUNm+lkeltJXLNrTXcBy6ztSC
         Nm6Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:feedback-id:x-gm-message-state:sender:from:to:cc
         :subject:date;
        bh=kOrAmzNniU0YMSnSqeFp9QoMr+5tlqk6QgkXyUq8V2A=;
        b=hhzQwYJ2OVs7to+BSxZY4tKEHpL3n+yXyWXKXA+54Hz7Ul4bm4jqcIzISPB37MGHKW
         vAxdlDRhx89gcowYEB8zj9Ej+eTDmDvBHRvWuwDFyq+x4WqOmXpOxECusciAxS+96qfa
         spy6zNHBGTVin/lnWTjHm7+0DFzioBTrLnnkLSMB5lTtz/Fp8MpsVO52cUMgUxKj7PAy
         s8BJraUOduqLZaCo3hKQ/xdmwAdAK+0gCprBJh7YxoRZbyOa4+fvXp10KlTecMgMydOI
         DkG6oFVUi9Ati+Zlf27M7xa7S/nvIAAT/qy/w2BxTDp3A8DhkdSENpomafEXF23dVRw5
         3DUQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACgBeo1d/TaGN/YEVKPQtRZC3U3HNEo0WN/DkDYsTDPHlcmty/6Mh6mw
	jEYgrF+fMz7EBYfSbx2RV7g=
X-Google-Smtp-Source: AA6agR5MbCVGygLAEVTD5o3PvkAYftJCmmcy3NIREzmxRUZLxAPtWtoxz2IN6BjAAFHnZoHRhpBZfg==
X-Received: by 2002:a05:6a00:420c:b0:53e:7db4:acd2 with SMTP id cd12-20020a056a00420c00b0053e7db4acd2mr3442046pfb.62.1662572564016;
        Wed, 07 Sep 2022 10:42:44 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:f78c:b0:172:8d81:7e5b with SMTP id
 q12-20020a170902f78c00b001728d817e5bls8696467pln.6.-pod-prod-gmail; Wed, 07
 Sep 2022 10:42:43 -0700 (PDT)
X-Received: by 2002:a17:902:ab8e:b0:174:11d5:b2ec with SMTP id f14-20020a170902ab8e00b0017411d5b2ecmr4883509plr.18.1662572563167;
        Wed, 07 Sep 2022 10:42:43 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1662572563; cv=none;
        d=google.com; s=arc-20160816;
        b=UiD8kY0qMAsvkB5lzz9v8Ik5/1Y+Et7uHGPcSTWgRZP7KqefJTM1+p3YibU0i1sBT1
         bT1Y/imhDYtOtXlANOU+1uuqAWGxbTxD5oxF0sQgVBXS9fDh7OpIdtEO3Ovg4qejWqtu
         X+uYRpnlWTMMFqGp6dM76aIlPMtnvQ0Csgyzaa98hXPHuEua+NxiJFrlCC/eKhmrhXdh
         8x1JXFpT+/iBTeVHDxLfhcQAIRRNCWqA5A5QaaC2MwHW6/ZkvDxZ/4I9UAR1TT43Jw55
         kKH3Wup+vPrHZvVz+zZp1Xwk7WQsGWxlNmfVAZFvTTnqD6/N0+dCplsP77aFv/glkrnn
         Zfdw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:feedback-id:dkim-signature;
        bh=YX6bb2S/xfOxRCtWHv2IUtfoGGrWjC9MoUuuhHCU2UQ=;
        b=ddB5+0hdYxun/uertpJ+WnF/6ukJjEADg5w1+pkCkgcyGfeFWPiEjxgPVu82YSAg3y
         GnZ3N3qecoxHNZBMUOquim2hBK6kPTppguEqVepmCihl4N6cQJot+z1AVlNGjLYhjSBo
         p4M87GV7A4RmQHdLFXvrEikxeZU/7UXXWOVUWsKTMIcbmQc1H4XbQmp5+0W7Z1Fpjz1e
         DhkO6Gpyo3WunHQ6Jm985tnR9x6yopdX6A7qbfiqk2yeHk3U8TA9b69Csj8cqUMsT3cZ
         TzKwKSu0r1g1aul9oLaEgjaNOlUkEfuxmSUQFLueFGHH8obG7gUfCvWF19DoCzCjulDu
         EBpA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=gRbEXFRf;
       spf=pass (google.com: domain of boqun.feng@gmail.com designates 2607:f8b0:4864:20::72a as permitted sender) smtp.mailfrom=boqun.feng@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-qk1-x72a.google.com (mail-qk1-x72a.google.com. [2607:f8b0:4864:20::72a])
        by gmr-mx.google.com with ESMTPS id c144-20020a621c96000000b0051c55b05eaesi1119296pfc.5.2022.09.07.10.42.43
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 07 Sep 2022 10:42:43 -0700 (PDT)
Received-SPF: pass (google.com: domain of boqun.feng@gmail.com designates 2607:f8b0:4864:20::72a as permitted sender) client-ip=2607:f8b0:4864:20::72a;
Received: by mail-qk1-x72a.google.com with SMTP id a15so11044120qko.4
        for <kasan-dev@googlegroups.com>; Wed, 07 Sep 2022 10:42:43 -0700 (PDT)
X-Received: by 2002:a37:888:0:b0:6bc:68cf:cdf5 with SMTP id 130-20020a370888000000b006bc68cfcdf5mr3634651qki.639.1662572562418;
        Wed, 07 Sep 2022 10:42:42 -0700 (PDT)
Received: from auth1-smtp.messagingengine.com (auth1-smtp.messagingengine.com. [66.111.4.227])
        by smtp.gmail.com with ESMTPSA id 137-20020a37078f000000b006be68f9bdddsm14132067qkh.133.2022.09.07.10.42.41
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 07 Sep 2022 10:42:41 -0700 (PDT)
Received: from compute2.internal (compute2.nyi.internal [10.202.2.46])
	by mailauth.nyi.internal (Postfix) with ESMTP id 6A19827C0054;
	Wed,  7 Sep 2022 13:42:41 -0400 (EDT)
Received: from mailfrontend2 ([10.202.2.163])
  by compute2.internal (MEProxy); Wed, 07 Sep 2022 13:42:41 -0400
X-ME-Sender: <xms:ENgYY3dM8qN4McFIlKxgrGKHGwEQ-XUKEMA0Ns6mWJmOCvqVd9W3JQ>
    <xme:ENgYY9OUh3bNzVLLOhGSeZYOFHK_4eqw7XxONjyjewVdSI3twWjjKzqNrcGBTnWYO
    40KDk4yBi31keYsuw>
X-ME-Received: <xmr:ENgYYwhIVGuyph65CiDFUcIOJIUHzvg9YIUQmkK3tnmZpJe2wc6SyhdgRyE>
X-ME-Proxy-Cause: gggruggvucftvghtrhhoucdtuddrgedvfedrfedttddgudduiecutefuodetggdotefrod
    ftvfcurfhrohhfihhlvgemucfhrghsthforghilhdpqfgfvfdpuffrtefokffrpgfnqfgh
    necuuegrihhlohhuthemuceftddtnecusecvtfgvtghiphhivghnthhsucdlqddutddtmd
    enucfjughrpeffhffvvefukfhfgggtuggjsehttdertddttddvnecuhfhrohhmpeeuohhq
    uhhnucfhvghnghcuoegsohhquhhnrdhfvghnghesghhmrghilhdrtghomheqnecuggftrf
    grthhtvghrnhephedugfduffffteeutddvheeuveelvdfhleelieevtdeguefhgeeuveei
    udffiedvnecuvehluhhsthgvrhfuihiivgeptdenucfrrghrrghmpehmrghilhhfrhhomh
    epsghoqhhunhdomhgvshhmthhprghuthhhphgvrhhsohhnrghlihhthidqieelvdeghedt
    ieegqddujeejkeehheehvddqsghoqhhunhdrfhgvnhhgpeepghhmrghilhdrtghomhesfh
    higihmvgdrnhgrmhgv
X-ME-Proxy: <xmx:ENgYY49H3QeRpKRT65ZH5w7_29d5-kxwUndoU3Bzr5jtdFGsrFLe7A>
    <xmx:ENgYYzu2mV1jT2aotsWVho2XKn2X2y0zxKVmu3nVsrsi2pJXJgNfYw>
    <xmx:ENgYY3E1dp3ptyxFD6CkJ-4YowLQCwXnkwo6_sXbybOsS_T6s5nH2Q>
    <xmx:EdgYYxJqn-PNxH2D45lojcoiEhJnwZHVNhTqQb3JBoQ3LTkg-82Fgg>
Feedback-ID: iad51458e:Fastmail
Received: by mail.messagingengine.com (Postfix) with ESMTPA; Wed,
 7 Sep 2022 13:42:40 -0400 (EDT)
Date: Wed, 7 Sep 2022 10:41:20 -0700
From: Boqun Feng <boqun.feng@gmail.com>
To: Marco Elver <elver@google.com>
Cc: "Paul E. McKenney" <paulmck@kernel.org>,
	Mark Rutland <mark.rutland@arm.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Alexander Potapenko <glider@google.com>, kasan-dev@googlegroups.com,
	linux-kernel@vger.kernel.org, Nathan Chancellor <nathan@kernel.org>,
	Nick Desaulniers <ndesaulniers@google.com>, llvm@lists.linux.dev
Subject: Re: [PATCH 2/2] objtool, kcsan: Add volatile read/write
 instrumentation to whitelist
Message-ID: <YxjXwBXpejAP6zoy@boqun-archlinux>
References: <20220907173903.2268161-1-elver@google.com>
 <20220907173903.2268161-2-elver@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20220907173903.2268161-2-elver@google.com>
X-Original-Sender: boqun.feng@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b=gRbEXFRf;       spf=pass
 (google.com: domain of boqun.feng@gmail.com designates 2607:f8b0:4864:20::72a
 as permitted sender) smtp.mailfrom=boqun.feng@gmail.com;       dmarc=pass
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

On Wed, Sep 07, 2022 at 07:39:03PM +0200, Marco Elver wrote:
> Adds KCSAN's volatile barrier instrumentation to objtool's uaccess

Confused. Are things like "__tsan_volatile_read4" considered as
"barrier" for KCSAN?

Regards,
Boqun

> whitelist.
> 
> Recent kernel change have shown that this was missing from the uaccess
> whitelist (since the first upstreamed version of KCSAN):
> 
>   mm/gup.o: warning: objtool: fault_in_readable+0x101: call to __tsan_volatile_write1() with UACCESS enabled
> 
> Fixes: 75d75b7a4d54 ("kcsan: Support distinguishing volatile accesses")
> Signed-off-by: Marco Elver <elver@google.com>
> ---
>  tools/objtool/check.c | 10 ++++++++++
>  1 file changed, 10 insertions(+)
> 
> diff --git a/tools/objtool/check.c b/tools/objtool/check.c
> index e55fdf952a3a..67afdce3421f 100644
> --- a/tools/objtool/check.c
> +++ b/tools/objtool/check.c
> @@ -999,6 +999,16 @@ static const char *uaccess_safe_builtin[] = {
>  	"__tsan_read_write4",
>  	"__tsan_read_write8",
>  	"__tsan_read_write16",
> +	"__tsan_volatile_read1",
> +	"__tsan_volatile_read2",
> +	"__tsan_volatile_read4",
> +	"__tsan_volatile_read8",
> +	"__tsan_volatile_read16",
> +	"__tsan_volatile_write1",
> +	"__tsan_volatile_write2",
> +	"__tsan_volatile_write4",
> +	"__tsan_volatile_write8",
> +	"__tsan_volatile_write16",
>  	"__tsan_atomic8_load",
>  	"__tsan_atomic16_load",
>  	"__tsan_atomic32_load",
> -- 
> 2.37.2.789.g6183377224-goog
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YxjXwBXpejAP6zoy%40boqun-archlinux.
