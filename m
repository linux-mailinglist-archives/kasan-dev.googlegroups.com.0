Return-Path: <kasan-dev+bncBCCMH5WKTMGRBGNF6LFQMGQEWZUNFMA@googlegroups.com>
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail.lfdr.de
	by lfdr with LMTP
	id AN0HEZySfGkQNwIAu9opvQ
	(envelope-from <kasan-dev+bncBCCMH5WKTMGRBGNF6LFQMGQEWZUNFMA@googlegroups.com>)
	for <lists+kasan-dev@lfdr.de>; Fri, 30 Jan 2026 12:14:36 +0100
X-Original-To: lists+kasan-dev@lfdr.de
Received: from mail-dl1-x123f.google.com (mail-dl1-x123f.google.com [IPv6:2607:f8b0:4864:20::123f])
	by mail.lfdr.de (Postfix) with ESMTPS id BC09FB9F2E
	for <lists+kasan-dev@lfdr.de>; Fri, 30 Jan 2026 12:14:35 +0100 (CET)
Received: by mail-dl1-x123f.google.com with SMTP id a92af1059eb24-124a38e8980sf2743159c88.0
        for <lists+kasan-dev@lfdr.de>; Fri, 30 Jan 2026 03:14:35 -0800 (PST)
ARC-Seal: i=3; a=rsa-sha256; t=1769771673; cv=pass;
        d=google.com; s=arc-20240605;
        b=PImkUwFQoeu+ojuyHTe1+x/cwbOj2bcrS6RHxkuPQOI1VFif29u1A0fVeSyzmupf9p
         y+JLDdc7ActkTbT+EcviJ5RVVriT1ihDwEDt1KTBevCiwUDt0f3MIgwGXLYCvirapeYo
         0dq6GUNYREMYlu4UpIDFEzh0nHdYnC6N57yCnMfqmjvQgccTGQ++ieFF+xUd+QuqkHzF
         8DBNWndBNqPesCXmnKaO5x9QkUWRl9LRh3vvlFA4sYO7lsVipFyU9xre7zQHogg017ma
         LS0Z6vuxmlhicXoq1Tdc5WEryAQJqmxOC3oYcLmObl1/NKo+7iYafruPXLoiBA6RMrFj
         sgFg==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=S15uwF2EgboNnXa7AA79xQ8uwxgAtDvNYmjlCBdz9+k=;
        fh=CJcqj822TYbm9XIwXVzhgc7XeDeQW91A/RFLhS/CrXQ=;
        b=YWr/EwJu6kO80cc38a8Mm1Jk3KLdFwad1d2MkKtB/zegyGIiGzzkXCubjAmbj/UJ2X
         ZegKMRL45bLUW22EthTlSVXFULZAzvrzK1AMWehBTJT39O0PeVTM6kBC74eW6GCnDBEE
         uEE3ke0pqSyzIypchtP3lFRHD7XTgrpgp8+Xg/BYCQ893PvM0+f43vcAgiEVo2eBBjT6
         313uc6NDqbhni7CxpEaduTj4x7Lgu7oniMeeA2zu0woi3VhCX9x4HJK6J0HNes/Ybdvv
         H2UAu2WIIlCDVXEdnEb0jP+980BG/CFuScmrHti4g69VsRRhguGFXqHjX2gwKLvC+1QW
         0zrw==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=q4KIMFS1;
       arc=pass (i=1);
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::1029 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1769771673; x=1770376473; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=S15uwF2EgboNnXa7AA79xQ8uwxgAtDvNYmjlCBdz9+k=;
        b=Ns4l2f058DtNkAokT9aWtlafjlwC76pO22uU/tNjjNuSvgePxde/V3zOj1xUoSLM1q
         ZT8pkmrM2Oq+oawGbExylrj4w2qYCXBi+piDyWTMmvTsZ2RWkigeHM2+LcsqSu78sZun
         NGOr8q+dVsvqlO8iMPQDD6GQpEtzqBfDmqqAw6xQCP3h/aF0bPlYEzsnEmAktgoUCOFs
         h2+1Y7r1WuNWtgr7UvA+KBj4X8zULErUEUIkPoffnDJY2t7zrJRtweVdUyUpbRjcOqMU
         OA1jxQpQHE6fS0CPeZ+nso4JgOrTxwu9DBLBC1ITdAm75ln8XDvwPVxVtmT7022BYjJJ
         4ErA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1769771673; x=1770376473;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-gm-gg:x-beenthere
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=S15uwF2EgboNnXa7AA79xQ8uwxgAtDvNYmjlCBdz9+k=;
        b=SvhB+qJoY1Jkx+Phqv8jn9Fhfu16WBmAuwBdf3YhabCSjsArXLDFnAA1m5OQRY/2Bt
         peDfqGOnumd2UQW9qjrSMlMATUYEhzBRhHfuYR/Lfr58+VMfesf3kn+eijIYC+fG8mlV
         vEOhdO7Le/zCwc4ESbAiV85WuNMA8cu2owNBd+6mDBey5sSsY9V+1VX1eLZmcQf3NfiR
         lQUkmUzDUikwQ3UwqlgXnKNVn+6rgrktC7uHO6kUQkbeexUyttqS9NedhRZMX1wdF2Cf
         IpGctDux3NWWTNfkWQeE+K6++LhB3q1jIrTehwKyZAmGCZx/Ta/FgcrkwYaoGn3WumPo
         rdZw==
X-Forwarded-Encrypted: i=3; AJvYcCVjZdLtsQkVaOMyXloxksSPJ2+juLxAG6LZWR2yKZFDmUGOqMzO3+tK9PqAusaswT0yCQO0zA==@lfdr.de
X-Gm-Message-State: AOJu0YxIUp85nNMr9VCiK2VAfyfuleW+1eW0cseGDpHFtUNRgZWszKN2
	jYKchp7g6zPfBE8qAlPpXgIcfj6WPQsDGbXIVt6h/3XV8MahL3kAPwI4
X-Received: by 2002:a05:7022:4392:b0:11c:b3ae:c9f1 with SMTP id a92af1059eb24-125c0f8c4c5mr1223555c88.1.1769771673484;
        Fri, 30 Jan 2026 03:14:33 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+EePuigswtHPZurXENHHgSpZ8vgQ7YmyTsdFAtSPDFz1g=="
Received: by 2002:a05:7022:ef16:b0:11b:50a:6265 with SMTP id
 a92af1059eb24-124b1b92b5cls999576c88.1.-pod-prod-06-us; Fri, 30 Jan 2026
 03:14:29 -0800 (PST)
X-Forwarded-Encrypted: i=3; AJvYcCVrmBKGACgap3wVkOVxGdq3kQtMMlSrlfYfKIOeL8CCs3cfQNSX/M6gc3sWNVBGfmsYrXnFAPvkRN0=@googlegroups.com
X-Received: by 2002:a05:7022:fa6:b0:123:3407:106d with SMTP id a92af1059eb24-125c1001033mr962219c88.28.1769771669567;
        Fri, 30 Jan 2026 03:14:29 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1769771669; cv=pass;
        d=google.com; s=arc-20240605;
        b=MoYqlRZXso0Cv4ztMb/ttQyQiZUf6THraaizUNS2iR5bqiUaYF1/TjESSGXQgCObdv
         rzsKsQPhRolRcWKDX78HkbCQUyCjbWFiGBiWyDpqwECAEwqnpsUV7yaORmPsqgfBWEse
         vy79CAg2tfWTAYZ90EvCSZhnoOTR+ErQOTDyFFKbSrStFqKkquW4esb3I9Q79N+Lbv8s
         hEWtZALb5pGThENuL1sf19mROcQ2JlxF6MM8krqJGDa8nuoaocVnIJttmkoDuuhuiEI/
         XDytvWoBqnSsew12phFflwGlwy3cZT+d1gqiRi/athvjzOf9l9qdyIa8miVJlHxeGmvl
         s5GQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=5NX6/8aQxy3kGKKmxgUb8QfLiJ2pU03lf0e4EyOMnpg=;
        fh=0DoRE8Ps0dLFt74PqjuO1YD0FH7WHWTbXM4vqSUlctg=;
        b=XNLFvakP6Y3e6u34yFOOy8ZqODhYrVSXkVp8Qu/uzzKfmVbq3SEaCQcnIs3u4CLBFR
         wbduhualSbzRgtchu7+I7LnToM1USstwOZ4nhiE5J46jG0W7eV60XoZLIETsZRWkFwHJ
         vmRigQNG13bn42XcKhuCNIRFgV5e3ASon8F9SglLPQhHG8vgIm6iqOHDCfHTT+uhaCMk
         9F+TsW7hb3tBvcc3Vx9SinrhelhSPvKkUwouRh2loVHvt7gM8zGemAZgqmywtUUeXFCO
         P8Nuc7gRxEg5tFVUyPFCyz/EFYKZ15SnCQcxN/lLweOt+UuZVYK0OaUip+p4G/TCphWc
         vBEA==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=q4KIMFS1;
       arc=pass (i=1);
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::1029 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pj1-x1029.google.com (mail-pj1-x1029.google.com. [2607:f8b0:4864:20::1029])
        by gmr-mx.google.com with ESMTPS id a92af1059eb24-124a9da842esi293043c88.2.2026.01.30.03.14.29
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 30 Jan 2026 03:14:29 -0800 (PST)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::1029 as permitted sender) client-ip=2607:f8b0:4864:20::1029;
Received: by mail-pj1-x1029.google.com with SMTP id 98e67ed59e1d1-34c1d98ba11so1617838a91.3
        for <kasan-dev@googlegroups.com>; Fri, 30 Jan 2026 03:14:29 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1769771669; cv=none;
        d=google.com; s=arc-20240605;
        b=NgBrV81htL855NS5LkZ/jH7ixYc6NYOUc5Rs/j0ZVGvZvNrQthJBGtUcnVrV3lMU5E
         4QyHiriIt3uqOihjNvZt2b95pXl6pFE83gisUQ8YaHhg0M0Dx3OEUSkTnwbAglmOf7Rn
         NWwjirFbswndd0uG7Xom05dOFeFHriofrQMLHcAeE0MlNd/UsDQ0mQM1IFI70R2MCPa9
         7PCcEsG/REyTpvpljKYIS23pTz4ewmThtc63EN84ODulK8q0zncsLKdpGzlvMZ1j1CZS
         qP9up40r13XohpptuqF+1eqtyajfIkqueCNUwR7zNBOoTCRpjRLrlNzi1K5x3h8FBaC8
         NsGw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=5NX6/8aQxy3kGKKmxgUb8QfLiJ2pU03lf0e4EyOMnpg=;
        fh=0DoRE8Ps0dLFt74PqjuO1YD0FH7WHWTbXM4vqSUlctg=;
        b=EYqznTmYSiAGcGc5V1iHPrIGtBjAQkt7VYPwVnypaO5rFHZeILIIyF6En4pVxotdbl
         754PJGaUvgSeANrB0L59z7UDhb8AqsaT4iZJX93nkVX0sQ6No7XwROm7DhdWu+pSiV5d
         e1ROnoDD6PoP8PPuu3ZtdnDscht9BrLbvnnyEOYsslVnez+XGcDoLDmoMe8DMTJZTxBs
         bjg4VoLUaL0O5O54jRCTNQFExbAaNbgWqvtlnx8TYbUtN90+lcZwl5SvPQRFcqQeZojT
         vaEpJv5inBqaiMO7Cvb97NL6kqzFt6uv89C51ZhyKObuUbUNKp29ijgiuFI79tdBL7BO
         J72A==;
        dara=google.com
ARC-Authentication-Results: i=1; mx.google.com; arc=none
X-Forwarded-Encrypted: i=1; AJvYcCVXFjFuh1apIRISb3Q809nhbO3t7XtkWQbvbyYIwaLD9bsBhwW44AP8I4kxjlus981IVi0Pm4Hrc8k=@googlegroups.com
X-Gm-Gg: AZuq6aJIlAto3UsK+xEArLjqvvvq8XPdPmdNyyYvxIFeh6EO7C631vmY0dtWQWvHaRE
	69dYUN3hRegqbcozmoa4ILz73X3KH0xldOxp5ZsyHna2yHE66kOvdWQMY1eJtasKFhIotkRAftx
	vJLvovM6lTxJRFt38/Bx5j/SstLYV/BZklPz0mLlEf973oXh9qDOOD25f739YkDbrQS1tEouAXc
	0C8Nb0JE2MpvdRVJ4ePXEsLVmke0acp68bcR7GIndwro6aZSavjrxt911h1H+DW4HHJEiCy15dH
	+0oBuJMgmRos/iFEGur5R7M5hg==
X-Received: by 2002:a17:90b:3c43:b0:352:ccae:fe65 with SMTP id
 98e67ed59e1d1-3543b2dee06mr2832480a91.4.1769771668673; Fri, 30 Jan 2026
 03:14:28 -0800 (PST)
MIME-Version: 1.0
References: <20260112192827.25989-1-ethan.w.s.graham@gmail.com> <CAG_fn=W6wdFHYsEqkS37iWOkJUZqS0LUEg-N2HWo+3Rw-76v4A@mail.gmail.com>
In-Reply-To: <CAG_fn=W6wdFHYsEqkS37iWOkJUZqS0LUEg-N2HWo+3Rw-76v4A@mail.gmail.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 30 Jan 2026 12:13:49 +0100
X-Gm-Features: AZwV_Qg0luMSY0y1N1xh2lvqYlNWV--Rlx3KALTJGGklX1gYVl6nq4JAZoKUMIQ
Message-ID: <CAG_fn=URHwuOuF_RNyxDCJZmjAFKSf4kHau6uTsFFPrTB=3-Kw@mail.gmail.com>
Subject: Re: [PATCH v4 0/6] KFuzzTest: a new kernel fuzzing framework
To: shuah@kernel.org, skhan@linuxfoundation.org
Cc: akpm@linux-foundation.org, andreyknvl@gmail.com, andy@kernel.org, 
	andy.shevchenko@gmail.com, brauner@kernel.org, brendan.higgins@linux.dev, 
	davem@davemloft.net, davidgow@google.com, dhowells@redhat.com, 
	dvyukov@google.com, ebiggers@kernel.org, elver@google.com, 
	gregkh@linuxfoundation.org, herbert@gondor.apana.org.au, ignat@cloudflare.com, 
	jack@suse.cz, Ethan Graham <ethan.w.s.graham@gmail.com>, jannh@google.com, 
	johannes@sipsolutions.net, kasan-dev@googlegroups.com, kees@kernel.org, 
	kunit-dev@googlegroups.com, linux-crypto@vger.kernel.org, 
	linux-kernel@vger.kernel.org, linux-mm@kvack.org, lukas@wunner.de, 
	mcgrof@kernel.org, rmoar@google.com, sj@kernel.org, tarasmadan@google.com, 
	wentaoz5@illinois.edu
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=q4KIMFS1;       arc=pass
 (i=1);       spf=pass (google.com: domain of glider@google.com designates
 2607:f8b0:4864:20::1029 as permitted sender) smtp.mailfrom=glider@google.com;
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
X-Rspamd-Server: lfdr
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
	TAGGED_FROM(0.00)[bncBCCMH5WKTMGRBGNF6LFQMGQEWZUNFMA];
	FROM_HAS_DN(0.00)[];
	MIME_TRACE(0.00)[0:+];
	RCVD_COUNT_THREE(0.00)[4];
	TO_DN_SOME(0.00)[];
	RCPT_COUNT_TWELVE(0.00)[33];
	FREEMAIL_CC(0.00)[linux-foundation.org,gmail.com,kernel.org,linux.dev,davemloft.net,google.com,redhat.com,linuxfoundation.org,gondor.apana.org.au,cloudflare.com,suse.cz,sipsolutions.net,googlegroups.com,vger.kernel.org,kvack.org,wunner.de,illinois.edu];
	REPLYTO_DOM_NEQ_TO_DOM(0.00)[];
	HAS_REPLYTO(0.00)[glider@google.com];
	TAGGED_RCPT(0.00)[kasan-dev];
	NEURAL_HAM(-0.00)[-1.000];
	FROM_EQ_ENVFROM(0.00)[];
	REPLYTO_DOM_NEQ_FROM_DOM(0.00)[];
	ASN(0.00)[asn:15169, ipnet:2607:f8b0::/32, country:US];
	FORGED_RECIPIENTS_MAILLIST(0.00)[];
	MISSING_XM_UA(0.00)[];
	DKIM_TRACE(0.00)[googlegroups.com:+];
	DBL_BLOCKED_OPENRESOLVER(0.00)[googlegroups.com:email,googlegroups.com:dkim,mail.gmail.com:mid,mail-dl1-x123f.google.com:helo,mail-dl1-x123f.google.com:rdns]
X-Rspamd-Queue-Id: BC09FB9F2E
X-Rspamd-Action: no action

On Tue, Jan 20, 2026 at 3:26=E2=80=AFPM Alexander Potapenko <glider@google.=
com> wrote:
>
> On Mon, Jan 12, 2026 at 8:28=E2=80=AFPM Ethan Graham <ethan.w.s.graham@gm=
ail.com> wrote:
> >
> > This patch series introduces KFuzzTest, a lightweight framework for
> > creating in-kernel fuzz targets for internal kernel functions.
> >
> > The primary motivation for KFuzzTest is to simplify the fuzzing of
> > low-level, relatively stateless functions (e.g., data parsers, format
> > converters) that are difficult to exercise effectively from the syscall
> > boundary. It is intended for in-situ fuzzing of kernel code without
> > requiring that it be built as a separate userspace library or that its
> > dependencies be stubbed out.
> >
> > Following feedback from the Linux Plumbers Conference and mailing list
> > discussions, this version of the framework has been significantly
> > simplified. It now focuses exclusively on handling raw binary inputs,
> > removing the complexity of the custom serialization format and DWARF
> > parsing found in previous iterations.
>
> Thanks, Ethan!
> I left some comments, but overall I think we are almost there :)
>
> A remaining open question is how to handle concurrent attempts to
> write data to debugfs.
> Some kernel functions may not support reentrancy, so we'll need to
> either document this limitation or implement proper per-test case
> locking.

Hi Shuah, I wanted to bring this series to your attention.
There are some comments to be addressed in v5, but overall, do you
think the code qualifies as "having no dependency on syzkaller"?

Thanks!

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
AG_fn%3DURHwuOuF_RNyxDCJZmjAFKSf4kHau6uTsFFPrTB%3D3-Kw%40mail.gmail.com.
