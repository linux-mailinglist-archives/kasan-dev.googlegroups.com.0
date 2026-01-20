Return-Path: <kasan-dev+bncBCCMH5WKTMGRBJVBX3FQMGQEEECWZBQ@googlegroups.com>
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail.lfdr.de
	by lfdr with LMTP
	id +FYINZ6hb2kLCAAAu9opvQ
	(envelope-from <kasan-dev+bncBCCMH5WKTMGRBJVBX3FQMGQEEECWZBQ@googlegroups.com>)
	for <lists+kasan-dev@lfdr.de>; Tue, 20 Jan 2026 16:39:10 +0100
X-Original-To: lists+kasan-dev@lfdr.de
Received: from mail-vs1-xe40.google.com (mail-vs1-xe40.google.com [IPv6:2607:f8b0:4864:20::e40])
	by mail.lfdr.de (Postfix) with ESMTPS id 635DD46522
	for <lists+kasan-dev@lfdr.de>; Tue, 20 Jan 2026 16:39:10 +0100 (CET)
Received: by mail-vs1-xe40.google.com with SMTP id ada2fe7eead31-5ec338650e0sf12342730137.0
        for <lists+kasan-dev@lfdr.de>; Tue, 20 Jan 2026 07:39:10 -0800 (PST)
ARC-Seal: i=3; a=rsa-sha256; t=1768923549; cv=pass;
        d=google.com; s=arc-20240605;
        b=bVh7dnPyWwbXh9HZ6e/8HDJtopEcWWRQCMnKeBb6VGIHzRYqei1A29jdC6gswUwfuH
         SSqY1W5483S+o8yhiK+3JavOAFVUYiRfEdDSs+qNwa4Zqajh33i9zh0nLYhdMmadIdtH
         ndBt2DLjhRxFPtu1s0Szio11KQGuWmrhY1fA/kMoNPU+yYvgVvW6ElS6jIOxIvGnVJzP
         vkswAh5UY0RyJgnjrpx+p2q+/Tst3vfkR6hKECh1X/Mpw7M7REV+JjJLPCIDawX5t5qL
         1H2ICsULzck3vEFogs91oXfLk0DB4LZmhlkJakDzFVrrCbY0S+fIo6EGeeWk4ftJv1F2
         9eFg==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=G5DMTxXRxIiiI6woEcaaLuVivXF1zdVIWdGjqD3BJ/I=;
        fh=UC9dao1C1LxtiElo88Ilzf9DYHoedcY3bChXqMoU49o=;
        b=Cg0Q1SvlhLRhhoM151bxCH5/hBL+HTn5I6gEe5Mxv95rEVxqx8ESn6550XoY2GU7v/
         pi2bkhgu8TxA6pSN1/yXoK1l6E20NBj5Iv28EWBQPyFd5REGmrE84YcqqNXaocFCJ9sA
         mKqCiVOWocCNCIM2d0iKMdyA8d2yban5LRD/7av4tCPaeW0FbX6gnchVPqHmFVJn4LE6
         5Ec7EsC4h0OK96SeBrHvgguQHUfs4WKyw0Jfw880jNQbFFxVsFTFkMYU/n88iY9YWUpd
         DMT8QxXxrqJlUWCbhg35EeRGwk2/bOZ2+UHsGbs+FLVJCmT34h8LGyMOCT5eTiwum39T
         sFNA==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=xlAKLihI;
       arc=pass (i=1);
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::82f as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1768923549; x=1769528349; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=G5DMTxXRxIiiI6woEcaaLuVivXF1zdVIWdGjqD3BJ/I=;
        b=f1mztl7gniGKKyWyJBpG3yP+zftJE/vwZedmRc7c9a+SvEatuDM4dsLQyVV8MPWWgK
         hKSUC0NyWuex32+svepxgm9/1cb/1oiEKUJRziRTKamPlc98AYl7GDTJXK0KIkuRpgiE
         +bDZWjNQWzc4rgVn7h30BBThePyDxPrlQZRrdi054Q/IAiY4WZTvTA8V5nyuiHYrhwLt
         FO1vlz0R7Z1oC9jMSNiSz3LwBBfLPbEiuY8tJCSlFiE6yFVe4+y3cfeEE3+6SJNKviWA
         TKORos6B5JwSZkLvD9YiWREX9hHHMszqwRnwPfNr+/vQb4Ss/KwU4c4JTxD/dezlWM79
         An1Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1768923549; x=1769528349;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-gm-gg:x-beenthere
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=G5DMTxXRxIiiI6woEcaaLuVivXF1zdVIWdGjqD3BJ/I=;
        b=YN9blL0dnMDdzlq1IxOqKK84Jv9MiZwdChJj/y/hpTt8N7mwa3guRtkcG1jgYr/RsL
         3rYXBfDLZEFpWav/XVZ7kvTvgyKwdf0t0UGiFDY+/9FkrwP7jTSGDWUqbNf6NXUjwDeL
         TKpNVIEOsjCBInVOvnKCRUVL6e2eEX2h5VqnzLQvD2vHavXPB84iSaApWRA5qFBbV9q/
         tBrl4LvUxd1PR7+1FzK7iFRJ874kbm0hOrURvL9F7KYbchcVJ0CFX2ytgJ+yvxkgAON1
         dUyutDPDb3M63FMwGZRX9hEDxYoqZISs2eDCa8aBJBlV/HFfo/bmT9924hqAtVZsIzxm
         onDQ==
X-Forwarded-Encrypted: i=3; AJvYcCVLGT0U89mWDwdGTtB3nXuZWSQ7Gq4etcsgoahW8YngQCOtOqwd4UAzHhC9dyTrBvdnFe+kQA==@lfdr.de
X-Gm-Message-State: AOJu0Yy0oRqVGXS9zPxLzIbfIv4QxiNZ7GTcFI7saiAudGF1Id8r5A/G
	pozeQIHFMeN8gUapeERzeL9FsgEoV77z3rR37MocEhokZ2ugsz/JnuQT
X-Received: by 2002:a53:ec0a:0:b0:63f:b9d1:b153 with SMTP id 956f58d0204a3-649177113d5mr8914175d50.40.1768919206958;
        Tue, 20 Jan 2026 06:26:46 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+H8YVZtlmldu6unlymQWEoiOn5CcB9X1Ctk09uJGVMFdg=="
Received: by 2002:a53:b80d:0:b0:63f:a0cf:c5f1 with SMTP id 956f58d0204a3-6490b93727fls4303265d50.2.-pod-prod-04-us;
 Tue, 20 Jan 2026 06:26:46 -0800 (PST)
X-Forwarded-Encrypted: i=3; AJvYcCUOMDQ66dbywGAC+JXAkZg1O4zBm7Lz7NteZIa8yb4zPEec7on88abCJoItl9R4uofVQvO3Jl4wX3c=@googlegroups.com
X-Received: by 2002:a05:690c:3701:b0:794:35b:af87 with SMTP id 00721157ae682-794035bb38dmr25971917b3.63.1768919205866;
        Tue, 20 Jan 2026 06:26:45 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1768919205; cv=pass;
        d=google.com; s=arc-20240605;
        b=SHhulssQmxDpGtmyq+J0u8jluRVnRBLTJl56U3fwzIbwNmeKEEdk+KS8T7T99DPH/G
         Xmq0FbbThX+6gDoTEKIpv7zLe0b+1/6YbL179oCOCK+Lelyc5GalBeIXA568ycLKXLzD
         OgikvEwS9iq21eeSQL83fjqEVwtbJiZ1XZ7HoCy+NJwnty9ZiSPBOa7TiXOSA7dsHyUg
         nVrfgzq171Y22zq4idJGlFgBwCzfAGzHn561JLfgTk0FcfTQ/6QBdANH/TR9BW585NL0
         JXMAtRBDe1MIBb/8TNxWVutuS14oYYi/ugXUo4beCaULCiCu4Jw80G9XSjYugI+V6tOw
         7GSA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=iRq3V9TGTshUsvROKLlwVrfXJ6Y0o2eUwLmYrdqr/HA=;
        fh=zDQecXESxPZh8ReqdyBGZLvRqAzdlFNBCcvlAdeRfjE=;
        b=RlAq9RZzVzhL6kzXrHnzSN+Lc+uDWNPBn4KJWIMkpfmLRU7LcNVAiqqIA+MmoLcrb+
         Rf47yo3nqIbesU3wJnxF7FLZiNB05Pk4L5ESvEajwxvbY2e+7f+TRmWdFKYShahaBR0l
         1a2EUys5T7QA5To6Zu/1k7djleBSVC2n/zpEOr7GIjpGSqyZy/IRHPP3Zu1NdWUVEWzJ
         ZQDMkIip+c/HpC0UsH5wrottpbWsozkpChGAQ10mfHNyPMTCjiwwdgekH1DYnQmukbVz
         XGOhpMRi0ip+7kKerVjBXPXtXiUTeV/As/rMe1ivI+43GrHHN3OlREewZAF0q5Soz42Q
         BJqw==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=xlAKLihI;
       arc=pass (i=1);
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::82f as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-qt1-x82f.google.com (mail-qt1-x82f.google.com. [2607:f8b0:4864:20::82f])
        by gmr-mx.google.com with ESMTPS id 00721157ae682-793c66e21f8si4034767b3.2.2026.01.20.06.26.45
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 20 Jan 2026 06:26:45 -0800 (PST)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::82f as permitted sender) client-ip=2607:f8b0:4864:20::82f;
Received: by mail-qt1-x82f.google.com with SMTP id d75a77b69052e-50150bc7731so82132391cf.1
        for <kasan-dev@googlegroups.com>; Tue, 20 Jan 2026 06:26:45 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1768919205; cv=none;
        d=google.com; s=arc-20240605;
        b=ClAlUdpTX8GUso5KrQMvtJjsv32ht8eNQuK4u0CGesr1G9wuF4yut3umUbmbVi8znA
         r38XEqaf2Cj4b90bfRbrgExbem1op/e8ix5IhwbGQUKYi5NiIzZWSZO+3mjYRKPbLIwW
         Q5zr39hJG0Wg1zHHA0/WBJQwJiRLmmolbZB76kkqnP7qt5WfXxVMldD7MBXwWMCScsXI
         MhnyyAF1KHZ6RQhtl/itThfLG8Pg4v4tNTIlU5cUdU7s/Pfvg8IR10QYIJxsnRcgEUH4
         GteLVGR9PdLXdpdBozmg0cH5cVmrv04W698+JuglBLyq2zfD8bl35UMCTa2J6ve5kDUf
         rJ7A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=iRq3V9TGTshUsvROKLlwVrfXJ6Y0o2eUwLmYrdqr/HA=;
        fh=zDQecXESxPZh8ReqdyBGZLvRqAzdlFNBCcvlAdeRfjE=;
        b=azG2zqBZjbUcbfyvm+vW8+T/u5XIrmdmUddsgrE5od8wnmADb1aY45rW0MSQj2oNT1
         XLRABYB/t4VRsNilbO2Ub+Nc0a8OdoBxHxywrG24My7+SPfwRtYpAngtcnVgvNKOT+6+
         yJuaTD6v/Z3EM/RvfZdDeS1NdpxNL6kP6XPYgwXXkI8pWyxrBW4AlLIE2NX/lEAz89aG
         qB9z/FpFQIK2itgtrSeP04HhTXptHWsZfAWcMG9+xWruoONleVfTX/0Bsa4y53YHJQgj
         nctOtR6NNh/djPuIxENXToEfx9kmW3MhwHbXjCfQu/REgSSXDxnjSbTvYwgSQ/VuDdP1
         nGyQ==;
        dara=google.com
ARC-Authentication-Results: i=1; mx.google.com; arc=none
X-Forwarded-Encrypted: i=1; AJvYcCX5IzUeXvt+zc6lYQ928/CL5m5m88wJKxZRp0kFvV6R6afwa3FLIteyCGb1x0Km1VVprII8UJMJpNA=@googlegroups.com
X-Gm-Gg: AY/fxX7XsJlngWW1Z4vFC7uONRPtDwfQ4wZr36MHz10SNKgGrwfxV0xGTAl6HFin7Bb
	O/MX4IEtU7G+wkI9P6ZpsxdB7VAmTPJwrXQc+if6UP4u8fN4U4RAVuw7rXjor+WIA3ECQB7WXKD
	qYF5Aj1Twzx1suOhD7QJr9UsM2EQxW4fTOYUMuBSjKPnCZ8JTOsRoyLh64eqpzDqXOYf4omaKSK
	jkDgHlJwb7IdhN+6808jJRXPmwFoHmtRBEcYcbbmlwg1z9geRTp4RXUNpfF2mKjlGdsJzG408xh
	i2XyAcuYP/+M038FOrewiaAY
X-Received: by 2002:ac8:7d56:0:b0:501:426b:d497 with SMTP id
 d75a77b69052e-502a1f2213fmr247099121cf.52.1768919204813; Tue, 20 Jan 2026
 06:26:44 -0800 (PST)
MIME-Version: 1.0
References: <20260112192827.25989-1-ethan.w.s.graham@gmail.com>
In-Reply-To: <20260112192827.25989-1-ethan.w.s.graham@gmail.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 20 Jan 2026 15:26:07 +0100
X-Gm-Features: AZwV_QhNTGTWINIBPMZao5ljKIiGVxjHAO6q_kPP3h9eB_FkxoIYM4qby5HyYlU
Message-ID: <CAG_fn=W6wdFHYsEqkS37iWOkJUZqS0LUEg-N2HWo+3Rw-76v4A@mail.gmail.com>
Subject: Re: [PATCH v4 0/6] KFuzzTest: a new kernel fuzzing framework
To: Ethan Graham <ethan.w.s.graham@gmail.com>
Cc: akpm@linux-foundation.org, andreyknvl@gmail.com, andy@kernel.org, 
	andy.shevchenko@gmail.com, brauner@kernel.org, brendan.higgins@linux.dev, 
	davem@davemloft.net, davidgow@google.com, dhowells@redhat.com, 
	dvyukov@google.com, ebiggers@kernel.org, elver@google.com, 
	gregkh@linuxfoundation.org, herbert@gondor.apana.org.au, ignat@cloudflare.com, 
	jack@suse.cz, jannh@google.com, johannes@sipsolutions.net, 
	kasan-dev@googlegroups.com, kees@kernel.org, kunit-dev@googlegroups.com, 
	linux-crypto@vger.kernel.org, linux-kernel@vger.kernel.org, 
	linux-mm@kvack.org, lukas@wunner.de, mcgrof@kernel.org, rmoar@google.com, 
	shuah@kernel.org, sj@kernel.org, skhan@linuxfoundation.org, 
	tarasmadan@google.com, wentaoz5@illinois.edu
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=xlAKLihI;       arc=pass
 (i=1);       spf=pass (google.com: domain of glider@google.com designates
 2607:f8b0:4864:20::82f as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
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
X-Spamd-Result: default: False [-0.71 / 15.00];
	SUSPICIOUS_RECIPS(1.50)[];
	ARC_ALLOW(-1.00)[google.com:s=arc-20240605:i=3];
	DMARC_POLICY_ALLOW(-0.50)[googlegroups.com,none];
	R_SPF_ALLOW(-0.20)[+ip6:2607:f8b0:4000::/36];
	MAILLIST(-0.20)[googlegroups];
	R_DKIM_ALLOW(-0.20)[googlegroups.com:s=20230601];
	MIME_GOOD(-0.10)[text/plain];
	HAS_LIST_UNSUB(-0.01)[];
	RCVD_TLS_LAST(0.00)[];
	TAGGED_FROM(0.00)[bncBCCMH5WKTMGRBJVBX3FQMGQEEECWZBQ];
	RCVD_COUNT_THREE(0.00)[4];
	FREEMAIL_TO(0.00)[gmail.com];
	TO_DN_SOME(0.00)[];
	MIME_TRACE(0.00)[0:+];
	RCPT_COUNT_TWELVE(0.00)[33];
	FROM_HAS_DN(0.00)[];
	REPLYTO_DOM_NEQ_FROM_DOM(0.00)[];
	HAS_REPLYTO(0.00)[glider@google.com];
	ASN(0.00)[asn:15169, ipnet:2607:f8b0::/32, country:US];
	TAGGED_RCPT(0.00)[kasan-dev];
	FROM_EQ_ENVFROM(0.00)[];
	FREEMAIL_CC(0.00)[linux-foundation.org,gmail.com,kernel.org,linux.dev,davemloft.net,google.com,redhat.com,linuxfoundation.org,gondor.apana.org.au,cloudflare.com,suse.cz,sipsolutions.net,googlegroups.com,vger.kernel.org,kvack.org,wunner.de,illinois.edu];
	MISSING_XM_UA(0.00)[];
	REPLYTO_DOM_NEQ_TO_DOM(0.00)[];
	FORGED_RECIPIENTS_MAILLIST(0.00)[];
	DKIM_TRACE(0.00)[googlegroups.com:+];
	DBL_BLOCKED_OPENRESOLVER(0.00)[googlegroups.com:email,googlegroups.com:dkim,mail.gmail.com:mid]
X-Rspamd-Queue-Id: 635DD46522
X-Rspamd-Action: no action
X-Rspamd-Server: lfdr

On Mon, Jan 12, 2026 at 8:28=E2=80=AFPM Ethan Graham <ethan.w.s.graham@gmai=
l.com> wrote:
>
> This patch series introduces KFuzzTest, a lightweight framework for
> creating in-kernel fuzz targets for internal kernel functions.
>
> The primary motivation for KFuzzTest is to simplify the fuzzing of
> low-level, relatively stateless functions (e.g., data parsers, format
> converters) that are difficult to exercise effectively from the syscall
> boundary. It is intended for in-situ fuzzing of kernel code without
> requiring that it be built as a separate userspace library or that its
> dependencies be stubbed out.
>
> Following feedback from the Linux Plumbers Conference and mailing list
> discussions, this version of the framework has been significantly
> simplified. It now focuses exclusively on handling raw binary inputs,
> removing the complexity of the custom serialization format and DWARF
> parsing found in previous iterations.

Thanks, Ethan!
I left some comments, but overall I think we are almost there :)

A remaining open question is how to handle concurrent attempts to
write data to debugfs.
Some kernel functions may not support reentrancy, so we'll need to
either document this limitation or implement proper per-test case
locking.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
AG_fn%3DW6wdFHYsEqkS37iWOkJUZqS0LUEg-N2HWo%2B3Rw-76v4A%40mail.gmail.com.
