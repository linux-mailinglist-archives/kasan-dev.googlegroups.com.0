Return-Path: <kasan-dev+bncBC7OBJGL2MHBBLOTY3EQMGQE7SZBFNA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x3e.google.com (mail-oa1-x3e.google.com [IPv6:2001:4860:4864:20::3e])
	by mail.lfdr.de (Postfix) with ESMTPS id E6127CA4449
	for <lists+kasan-dev@lfdr.de>; Thu, 04 Dec 2025 16:33:03 +0100 (CET)
Received: by mail-oa1-x3e.google.com with SMTP id 586e51a60fabf-3e82af7316bsf1468659fac.0
        for <lists+kasan-dev@lfdr.de>; Thu, 04 Dec 2025 07:33:03 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1764862382; cv=pass;
        d=google.com; s=arc-20240605;
        b=ZLnyy8m9zUyD/i2ThyzbBwPADDdJGIHe7aRnJ55SwM5SUeKCcuRERTl8DJmwZ0EDTh
         m+UAkyEaO4Zcu4WdBFIft0e5whoLuoN6P3u2yyx36vqto641EP9N0GKG/I12lCOkhM77
         5OWm6ejZz7NhDV+80qalUsgbL6ZPaVfqSFvnp0yxOMqSEg8zcmn3cBX+gWUIkT5Ntiub
         wG4EyhT9s7HyZKgr4kdq/pxcAbfaOBNcBR9i0A2nukDwZYU+Z3aQxTrFAxam2JXK6OsM
         57CgK8MdeFrZ2P3bFDYDhsSdIFl180aNP06Xgpp8LHZDjU5PWdoOWKoqKKto9371qQ+m
         vBVg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=rFQlcFQ2TkxDuMKkxWtQraT4hRTR1jZQdHIemj2R9zw=;
        fh=s+70y78H4ve1dIcH1Fd9f6HVz65/mcZ2TeS/Jm4z6Hs=;
        b=IkYDjXtpSoj9BDz8RBkE0N0SMtYnzPTtKISpbPaANeXNobRIm4pqgxeRQ5aD4k2FZE
         4isweWb43NYIGov38IOohS8s9y2vep2411V3FikTon+hcaLCkQ/V/YLczY0KH6RUbrvj
         +RZScVCGCELqLrImvitcI2QkiBhixLA9WSaAy/KUNnXmprRd7oNbS0wS89W1QESenIy8
         N10+UkIkEMZiHtmCGsHooTD0IzeF7e7ZeXwsIyxiOW8E5y8uOTI/c0TrDIBr6lEXfNXW
         CxHAQYi7eDRrB4dXvJtfk4dPOV0SRtJctG0lq/jtYhCtd2xMrE+j9Fse5T6xpspfyo3J
         MjWg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=rDiE52tl;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::430 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1764862382; x=1765467182; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=rFQlcFQ2TkxDuMKkxWtQraT4hRTR1jZQdHIemj2R9zw=;
        b=f9neEKpqua7AOJf/ph47Z7e3Di1Ondbe6iwp+T55lF/naxTfMOrUVo2DQMfDz5wz+E
         1P2aOCVJAhCkM4w2/fh4dvztRnpmFft5g8B92gglAmS9e8tBR9OyLBlQclo5wlcck6Co
         geVY3+FNS+pVf9fxuQYfG8215Emczp2UmP9eUrmvrZiZobsu1xi/0tKIsl0AZXoYHptj
         ++5D/4cMbx+ASUyUMm0NKCwrwbJi8g2rax+rUQJMLHO5YmHHDLYY0U/B2ofx2NBX1TB6
         4FzJnntBhNSOtSk59WAKvLY7qP09O8lYmwuToZc80bwA55Kqgm+9+Ai15oC4E4KPCdRr
         gRQA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1764862382; x=1765467182;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:x-gm-gg
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=rFQlcFQ2TkxDuMKkxWtQraT4hRTR1jZQdHIemj2R9zw=;
        b=hT4D36wgqUdivHvniQBOdEfet4iROctTsQlZWCU9fT6U11vcnl8IBGwAIazsNfs2JB
         +vpFQaGfwFA9/AEvVSsC0r6EAhf3F7yeImPcyPKJe8JOvxWwmpFX2my3dn8XnSkeOubX
         e6PQERpQqbWZWGkw67JPfGFOv660NzS8UdRZ0b3KDCvESdm31ij5IIKjQCPpSdqQpWTD
         Bt84NyJbEr762I4QwXTw6ht/W8O7ddJAwBblkHm+s9Rui+qihCX7amzE29Kum4hWSxfv
         2Y12Tyt938XGyo2c5yj71xe+pNQnnwTkd2FnX+zU0iaoWanfpBEdcwXqFacOQCjmdg2f
         sEfw==
X-Forwarded-Encrypted: i=2; AJvYcCWL+VNLYCRYtwO97MR/DcnNnA4Kbn0e9Eao4wJFNgl7bZ2pk1mkaxS2MtI1lT2QX6Oz49oveg==@lfdr.de
X-Gm-Message-State: AOJu0Yw44UYVSV8CfVx8/1Qszv5heeIw8FfGejUebLnxq+AkILJvGRHR
	xyUOtGk2dId5pRaAbSg/Sxmv2nu7I+WSt16/zsjfgkGjaVermy2K3XPH
X-Google-Smtp-Source: AGHT+IGaQ5Sew1JnKxqr+fP/TTOU5EWBlBnsF/YG0eYacxAbvU5ahE+MiP7S+PudP5sNgw8ZioY4eA==
X-Received: by 2002:a05:6870:2408:b0:3e7:e064:c264 with SMTP id 586e51a60fabf-3f506386d91mr2014920fac.12.1764862381865;
        Thu, 04 Dec 2025 07:33:01 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="Ae8XA+b5I0l+VhNFSZW1VGnEPeDWNLHRutuzVptT8wif3M7BgA=="
Received: by 2002:a05:6871:8fca:b0:331:5ba5:afd3 with SMTP id
 586e51a60fabf-3f50904863dls368732fac.1.-pod-prod-07-us; Thu, 04 Dec 2025
 07:33:00 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCXIGJehrfZ4045+JNxpAhnJAsS8HbxLyUXxIKTaWFLI4vmEgpyYss6zbEVF7MjGzOk+x5u6f2jdbTE=@googlegroups.com
X-Received: by 2002:a05:6830:314a:b0:7c6:a6fd:fcd6 with SMTP id 46e09a7af769-7c958afd5cfmr2619848a34.11.1764862380706;
        Thu, 04 Dec 2025 07:33:00 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1764862380; cv=none;
        d=google.com; s=arc-20240605;
        b=dtYE3h4uvuwvSgblIKEyuQ/mHzgSHqXYbk7RsHtMQqmtQVBNok0ZrPDY9grFO1ZZCU
         CZeUTGl/JnoqPPGVB+J2s8HvNGYxk5+bvK9c0yd2bxdCJTq5N58qy9FWEPNmY019rUay
         JjZqtV4QdQoAqRKTv53tOgmwvfXK1SsDB3ypzVu0mJ+CnDfaL3+pJMPhLEyTD/pux6l1
         Iw1eKVn/v1dTabnqQAZ+djpYHivmgs5Ga+3wiX6m8XD1kjBPAB0IocXse06TE/RNy3c8
         rQ9W0nLxrb97uhQDEJS3nyzq7AGzmLN6nwVzAs39qMZbktLNFPsDsiRghD4SV3fAGCHP
         uyWg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=ynmi+F4tSnwM3VjJVfL6w3FFtVt6Ah2F/7BtxBtZ4r4=;
        fh=EE6kWLsNDnr53uK8dTkhZxT6PpBXGKNXx62GIZdPeB8=;
        b=TJCAzlx1sK2a3v/Ryn//QYkynK8/5jkjQ3OvD/hEtH9i3Xf64MVwcbuYWMDo8vAvDq
         oA5RPmm5oARRv+tzhdWLwP4tladVO/ya/jKdwU5R0KUjbIUlNbEccjUfywzJf13hJ/x1
         jDMunXZzGmuNCSJeUkqAaR65pdFJ+t8MRM47lMdioxUFC7ZoK4yShdwP6LKMSliiGf4R
         Uuu7QJcg2LPW4cMRRY/RdRZoSBYoEbnz8KuHgfLgaYMCK9gqXApN2kQvPv7YsLzrw3K5
         yJMhkp1em5s5dRccrA7O/z0jPCGxkkU2zI1bIvHMb3pau7L37UBwgKrQSkurHADZ0Fh/
         YROQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=rDiE52tl;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::430 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pf1-x430.google.com (mail-pf1-x430.google.com. [2607:f8b0:4864:20::430])
        by gmr-mx.google.com with ESMTPS id 46e09a7af769-7c95a8fd59fsi122901a34.1.2025.12.04.07.33.00
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 04 Dec 2025 07:33:00 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::430 as permitted sender) client-ip=2607:f8b0:4864:20::430;
Received: by mail-pf1-x430.google.com with SMTP id d2e1a72fcca58-7b9c17dd591so898179b3a.3
        for <kasan-dev@googlegroups.com>; Thu, 04 Dec 2025 07:33:00 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCX0+Y1TdmiHlgEi/2CrERe6SLOaNV1z0aRtLdXYGBgGdSSB0ABrQgpu/2llhO4BaLcYUUFukt3XHRI=@googlegroups.com
X-Gm-Gg: ASbGncudq4Yyl1wOUYoakce6MoxwPCi21gJM1ut+2uNDM5734A1BSnAHLlCJEGKBEGd
	lAjNdwG8vn6GbU10aYq+5ee3ZcY+rici0HePMCcooRvNQ1wGJMBbBCJQX6WfIZuqSn8cADsz5hr
	cj6jdHnzgjkpzvLNfO0fbv8FKIsElrxU3CAm0+DcNv4jU9rjjR91qAAN169hiqu7EAO74/8n0wW
	ytYzrV8WDC2K7pkfEo+8SfU96rVHOPu3TkBQD0RSLq3wf95VHwvUpOllLp6wum2xknJxnLCh+zM
	Kk+UpK1yU2FwUAN8n+MN1XC4z226ZNu+3Q//
X-Received: by 2002:a05:7022:3808:b0:11d:f037:891c with SMTP id
 a92af1059eb24-11df64b94b7mr1985453c88.44.1764862379392; Thu, 04 Dec 2025
 07:32:59 -0800 (PST)
MIME-Version: 1.0
References: <20251204141250.21114-1-ethan.w.s.graham@gmail.com>
 <20251204141250.21114-10-ethan.w.s.graham@gmail.com> <CAHp75VfSkDvWVqi+W2iLJZhfe9+ZqSvTEN7Lh-JQbyKjPO6p_A@mail.gmail.com>
In-Reply-To: <CAHp75VfSkDvWVqi+W2iLJZhfe9+ZqSvTEN7Lh-JQbyKjPO6p_A@mail.gmail.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 4 Dec 2025 16:32:22 +0100
X-Gm-Features: AWmQ_bkpU_UzkQY7REuOUbS7OqCEAS3jlYqZDjlCZ9VHlEzHr8ON3cmhrcpo9_c
Message-ID: <CANpmjNMQDs8egBfCMH_Nx7gdfxP+N40Lf6eD=-25afeTcbRS+Q@mail.gmail.com>
Subject: Re: [PATCH 09/10] drivers/auxdisplay: add a KFuzzTest for parse_xy()
To: Andy Shevchenko <andy.shevchenko@gmail.com>
Cc: Ethan Graham <ethan.w.s.graham@gmail.com>, glider@google.com, andreyknvl@gmail.com, 
	andy@kernel.org, brauner@kernel.org, brendan.higgins@linux.dev, 
	davem@davemloft.net, davidgow@google.com, dhowells@redhat.com, 
	dvyukov@google.com, herbert@gondor.apana.org.au, ignat@cloudflare.com, 
	jack@suse.cz, jannh@google.com, johannes@sipsolutions.net, 
	kasan-dev@googlegroups.com, kees@kernel.org, kunit-dev@googlegroups.com, 
	linux-crypto@vger.kernel.org, linux-kernel@vger.kernel.org, 
	linux-mm@kvack.org, lukas@wunner.de, rmoar@google.com, shuah@kernel.org, 
	sj@kernel.org, tarasmadan@google.com, Ethan Graham <ethangraham@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=rDiE52tl;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::430 as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com;       dara=pass header.i=@googlegroups.com
X-Original-From: Marco Elver <elver@google.com>
Reply-To: Marco Elver <elver@google.com>
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

On Thu, 4 Dec 2025 at 16:26, Andy Shevchenko <andy.shevchenko@gmail.com> wrote:
[..]
> > Signed-off-by: Ethan Graham <ethangraham@google.com>
> > Signed-off-by: Ethan Graham <ethan.w.s.graham@gmail.com>
>
> I believe one of two SoBs is enough.

Per my interpretation of
https://docs.kernel.org/process/submitting-patches.html#developer-s-certificate-of-origin-1-1
it's required where the affiliation/identity of the author has
changed; it's as if another developer picked up the series and
continues improving it.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNMQDs8egBfCMH_Nx7gdfxP%2BN40Lf6eD%3D-25afeTcbRS%2BQ%40mail.gmail.com.
