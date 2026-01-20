Return-Path: <kasan-dev+bncBCCMH5WKTMGRBDM3X3FQMGQEZSQE7FI@googlegroups.com>
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail.lfdr.de
	by lfdr with LMTP
	id CF/oFKGob2kZEwAAu9opvQ
	(envelope-from <kasan-dev+bncBCCMH5WKTMGRBDM3X3FQMGQEZSQE7FI@googlegroups.com>)
	for <lists+kasan-dev@lfdr.de>; Tue, 20 Jan 2026 17:09:05 +0100
X-Original-To: lists+kasan-dev@lfdr.de
Received: from mail-dl1-x1240.google.com (mail-dl1-x1240.google.com [IPv6:2607:f8b0:4864:20::1240])
	by mail.lfdr.de (Postfix) with ESMTPS id D70B4471DC
	for <lists+kasan-dev@lfdr.de>; Tue, 20 Jan 2026 17:09:04 +0100 (CET)
Received: by mail-dl1-x1240.google.com with SMTP id a92af1059eb24-123840bf029sf7476265c88.1
        for <lists+kasan-dev@lfdr.de>; Tue, 20 Jan 2026 08:09:04 -0800 (PST)
ARC-Seal: i=3; a=rsa-sha256; t=1768925343; cv=pass;
        d=google.com; s=arc-20240605;
        b=XsJj/ZUszb+Axzs33z9spki8Eplqvz2rTsb+CFONkPkiVrhiyaLhF+fkOUzd5/q+R/
         wn1IJo3L1NWwr4C+hRHGu9acIRLmiVIyBzCwZB7x3D9wjhL34IVpXm1YUDE9ctIZpjNA
         VylE03awm2E0b/mlpE3hjV90IJ2qg4okZ6OW1RiDTXTLpw5eK3p6+2iC6kEQBS2HXFF+
         wnKnu+/ufmWseGnIBNCroPWQAlS7KJK11zAo8Id2Hyd1tPh741T5XfSs6OkRXVEvnSfy
         cawsOKGjeEvO5f5n8ck+fJ/kYPCkQmB4SqKvlVzu+LEJ6v2BkEhp7vmmhKlmtFsjN7VM
         HB4A==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=J8gmeaYWbHn0TepECIJUdOEqfZvEjT2stTC6y3WV5A0=;
        fh=0mv81bqB2F70TSnm7Frarloyc+mJ7mKLI8O6OHPHZ+8=;
        b=VkXQ69xmOdiJSF1Yctu8D91oTuVPJw+h5NwHRpPNPGGb9wdAWlEuCnqNwG8JNXexM3
         joEU9ZF+NmhmHkP5irSZM/fa84nLWBfsu1rWYxxKH78ooYT5y0X09NTF5UgeZ81fBdRJ
         736JP7u+yymlF0TBBip6Q1L0KUHAB4uHMJAmxHARxnGmE0gPDW0v64QYPoHbw0U968+j
         Y4olAi3oc3BwVGCyLx6bj179FYFTSffSi9mMLGjikTs+DS236RUKeVHFTLdD5tb+96eE
         GUh8F3l16ab022KkQb+SCrWiL8hbw604JCGz0G5BaCS+j0BYRGfNInj9B0ScNyi3ITtH
         GIxg==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=Dfxc1y8F;
       arc=pass (i=1);
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::735 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1768925343; x=1769530143; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=J8gmeaYWbHn0TepECIJUdOEqfZvEjT2stTC6y3WV5A0=;
        b=efliNKe8apzUwEQHiujZEeZQvfIq1kRAHn8rhfBYFwvRSzQY9gMPM72y+CSz5wKcbn
         S9MUqm+9xhFn/Jsr4IlHao7gnvjIevv9WPvr3MZH5jjT/Rg8g6xhHfvZ/BEAOIGh6D4F
         LMbwaVPacaD1LVH2/MSoBVFt9K7HWIkHDpIbDYImjfQM8QLCXLV8zrYfmb3bmwyFUYWs
         2s9SRjGMriDANGVWXVbMcdqEysNuhw0ZOOEt0mQxop5/KmX4A1MdxrPTEZFmv3cdGf5y
         f5kyMCafSxzwnvSTyU7fjW9Jl6A6GPafpI+lYiESPHF7tqKTjSdhopYoTZtZzjEyD/QN
         vgPw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1768925343; x=1769530143;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-gm-gg:x-beenthere
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=J8gmeaYWbHn0TepECIJUdOEqfZvEjT2stTC6y3WV5A0=;
        b=K3mXxlnmi73MkLJOADjmA/d8wtK260S2AhYZVdYryMMp/QcyybNUghfa4uFff2FRM7
         fkaxDKDQMWCd8zFcbHV+qCmKXFc0PBtPPfAp558g+WT43QWkEFHgLMyFEzf38NVbvuX8
         b5JjXVcCPf6SudRGByVzzUCi8ZJ2of1TzzxsUpugKvcSlZespIP8tqjeQGJT2kpNtDb0
         bk1zUfPFHHZbLpOVMEjJc2zoysEInbDO+uwu7sRwSObnOBwYH8PhDagOZwI0OwzohX7p
         QSITzLVCBppq6k2ysJnlnidwyH2sAfHzwBARdhjplFZGpuvbFh2VyA8qE3FkC6Y83Pi+
         kNDA==
X-Forwarded-Encrypted: i=3; AJvYcCWFnSf7ft9LxFkE+RmV2U9TPzFfCdVcqgyi/8y+fzMaxEIdjVD7D+EPb7Zi2fHTOIxBRwFr7w==@lfdr.de
X-Gm-Message-State: AOJu0Yz+x5ySLBCLvQUpKTpIaKOSY3hLwNjOVJv/KEB1RlYGfinj6FlZ
	aJxF/bkCthl7MeNEHzDu2Iu87xcAGwPIUisIrSKblMfjS+NlmEEaV7yq
X-Received: by 2002:a05:690e:148b:b0:63f:af33:e413 with SMTP id 956f58d0204a3-6491648342amr12775273d50.24.1768918414007;
        Tue, 20 Jan 2026 06:13:34 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+EsIxQgOBu9wX8LNgs3EaljhwPMQH+wsAFMC3OLw6DSCg=="
Received: by 2002:a53:b048:0:b0:641:f6b5:e319 with SMTP id 956f58d0204a3-6490b94a2e1ls4456207d50.3.-pod-prod-01-us;
 Tue, 20 Jan 2026 06:13:33 -0800 (PST)
X-Forwarded-Encrypted: i=3; AJvYcCVtVVTMKf+zi9+DELQ2kbeXPt8skuKWww2h7JNL6Uj/INhlxXx3cfAowZ8vftZguEc2nv5QRaJ1ptQ=@googlegroups.com
X-Received: by 2002:a05:690c:7288:b0:789:2be7:aec3 with SMTP id 00721157ae682-793c5394166mr117990747b3.35.1768918412922;
        Tue, 20 Jan 2026 06:13:32 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1768918412; cv=pass;
        d=google.com; s=arc-20240605;
        b=aTGJk/XtAX0aB5Eu2H6/EUoRob7tKwegAFCnMT+HgmpsFbhbdSzUnsN+FC8vYQDFuN
         lYUtuA7hgk+hVSfnzHZFJk/qpRg8s4/tzM3Pvx7B8dSy57E0kZ48ROsB1FAaqOng/6WG
         ANTXHGFMUDbdb/Ff50vzLJ+xGwfALEYjtPtn77Y5RDUzy/Xh5SzYFKhO/hLgh4Xs8Lk+
         ofFAISMV9k2FQeNv0eWC2uTiGfPWtLcVXcBiwDL62Kym0TyRzVJNQ1la8MxzlWNMnNc9
         hWHvbXw3bgRK64PiG5RKZzruxnfBRhPFbHxp95wtBD05l6L98w+6lN7uCB/lmQQGb50W
         6Skw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=IdYE5jdvNdfk3sHI8GmEWBpt99cM9oMrMqemVzHltu4=;
        fh=03ZymGBJmz2M3tsKVpJ75gaT2CvLV1yfMXohrd63BbY=;
        b=gHPz0Lj+5rXTMRdqCuKeh5W2xnMeFITcd2CowrFnc9Tj3cKIVzkA1Go/auMsaeHcAy
         2JHCvvKytyXbT0lJQblqhftFvFX2yFVJmRP+UmZpS4KdLA/H4DGQtJ7R79IqKvL2jpRz
         HuCqX7NyYFTbZrfbNOUcYi/l+ts7wwZV0AuSJMdYNJALtr/aGFUHKZ8OhuyVHonUDyDL
         BudojUaCnRhjwy7M4F4BsLhQuT5XtJO39jRsMrxeymSaznZqD12dVb0AgP7Jjs4icYar
         lo3GRRjJ0BZVhhZyiZmcgFfjzx5kffHsqiH+D2T0YIB0loc8b1O2VZTmTjjsjkfhQum3
         KA9g==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=Dfxc1y8F;
       arc=pass (i=1);
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::735 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-qk1-x735.google.com (mail-qk1-x735.google.com. [2607:f8b0:4864:20::735])
        by gmr-mx.google.com with ESMTPS id 00721157ae682-793c680fe06si4187547b3.5.2026.01.20.06.13.32
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 20 Jan 2026 06:13:32 -0800 (PST)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::735 as permitted sender) client-ip=2607:f8b0:4864:20::735;
Received: by mail-qk1-x735.google.com with SMTP id af79cd13be357-8c532d8be8cso509395885a.2
        for <kasan-dev@googlegroups.com>; Tue, 20 Jan 2026 06:13:32 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1768918412; cv=none;
        d=google.com; s=arc-20240605;
        b=HQEE9QzwX6zVLzm80Sck0ssm5Q9LbSHkMAott9mdR7STskgZ0GaZdt7IT54H6hphm8
         Mw4H/wYf6shKph1k+TG9JW0XU84Nr7oYVBvRwjMpDmzhlioDC4Bntp+V0SZQ8bsAxQwl
         SCPVvLumIWZNIzj7G3qiO6NTFKnT5KAlbmxK/tvfqOd3uiD+G1y6FVy2+PwIFIl6yOlq
         mCbjyHjlm3yamFGa5IZj7mU4aVl2N/geigPOyRv8FW/eQgcqJBwzXRKPM5Mw7YP8yEvK
         iEXJZCoyIAEewB6+57282B4ep+lp2HSsoHAs3qjhYH9iXYZonpr8QOAEYkkyoSDIi/rR
         0zSw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=IdYE5jdvNdfk3sHI8GmEWBpt99cM9oMrMqemVzHltu4=;
        fh=03ZymGBJmz2M3tsKVpJ75gaT2CvLV1yfMXohrd63BbY=;
        b=b0nCt3rbjFl8ePaN6AYgX2etIDstInfAFxY3h87SQ14LTUodaCZ4XEbz9qLzDXXJOr
         Tl3kXC6qAZ+ccpiLSN3YRHjgf29r8yGEAcJpSMr4dCx/aiTN0XKVkGcsbuJN566uoiu+
         MonMIGFyIHiz7658jozNgzs6tcNmg22YP7dZXCeFKRef8woJQQxnH73ztizpGSyuwQ/e
         cyEeZkU3XsLl0PrNyS8IaSlI+2yhjqI48cXvjX8WSRHZZAtFqFcnylG0vD76YTQ9l8kv
         mN5hG9hkZObM4lMK0uYhXNbkN09fKnb3a7SSZcGbu/acZKEsVPw8ewW2ihAfgHa2V7W9
         EGuQ==;
        dara=google.com
ARC-Authentication-Results: i=1; mx.google.com; arc=none
X-Forwarded-Encrypted: i=1; AJvYcCXmH18Zw+0r50FVWSpUHm+WrctayjqLLQ+UU+GVdRnS06/e/imxMq9zHDlum+QiAhuraWEZ2bZXD3M=@googlegroups.com
X-Gm-Gg: AZuq6aLlkt7abM9W8KMX8PkfCauMf7dha6lzdJFdYHX25CNFz0rKfYljMmdOhevvN2n
	u8M1vVU76JZQy4228o8riUH8gSqcgKtLhJ/Ug9sB5vIoG40QPbMctSI3SJuUUrM5lYGNtYXpFuC
	BK8KIZpdbN7UV63Y/GwqH8OAf/Kys6fVVty45Kwwi7685INU4JPjHtkvov94UPISvqoPucPh2ai
	S/NTleErEFZ3rduuq3vWxB6E5lXIq4D4UoSPczhoQmOsoCd6v6q4T8PEvrTwMPn1BBQ3/eKMpQu
	YaBJMmkqJ6F1om8/OmGfKPI324KL7cbIEd0=
X-Received: by 2002:a05:6214:202b:b0:894:68cf:49fc with SMTP id
 6a1803df08f44-89468cf5432mr19791426d6.23.1768918411939; Tue, 20 Jan 2026
 06:13:31 -0800 (PST)
MIME-Version: 1.0
References: <20260112192827.25989-1-ethan.w.s.graham@gmail.com> <20260112192827.25989-7-ethan.w.s.graham@gmail.com>
In-Reply-To: <20260112192827.25989-7-ethan.w.s.graham@gmail.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 20 Jan 2026 15:12:55 +0100
X-Gm-Features: AZwV_QhSRG2StFyNZkwjvq48dDIr-HhWGfUMqppHNhj04WZytkphQv9nwByXueo
Message-ID: <CAG_fn=VdRkSjvhO7wz7_PEznBOFgLjHCr2hSXwrKoO-hpMqTzg@mail.gmail.com>
Subject: Re: [PATCH v4 6/6] MAINTAINERS: add maintainer information for KFuzzTest
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
 header.i=@google.com header.s=20230601 header.b=Dfxc1y8F;       arc=pass
 (i=1);       spf=pass (google.com: domain of glider@google.com designates
 2607:f8b0:4864:20::735 as permitted sender) smtp.mailfrom=glider@google.com;
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
	TAGGED_FROM(0.00)[bncBCCMH5WKTMGRBDM3X3FQMGQEZSQE7FI];
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
	DBL_BLOCKED_OPENRESOLVER(0.00)[mail.gmail.com:mid,googlegroups.com:email,googlegroups.com:dkim]
X-Rspamd-Queue-Id: D70B4471DC
X-Rspamd-Action: no action
X-Rspamd-Server: lfdr

On Mon, Jan 12, 2026 at 8:28=E2=80=AFPM Ethan Graham <ethan.w.s.graham@gmai=
l.com> wrote:
>
> Add myself as maintainer and Alexander Potapenko as reviewer for
> KFuzzTest.
>
> Signed-off-by: Ethan Graham <ethan.w.s.graham@gmail.com>
> Acked-by: Alexander Potapenko <glider@google.com>
>
> ---
> PR v4:
> - Remove reference to the kfuzztest-bridge tool that has been removed
> PR v3:
> - Update MAINTAINERS to reflect the correct location of kfuzztest-bridge
>   under tools/testing as pointed out by SeongJae Park.
> ---
> ---
>  MAINTAINERS | 7 +++++++
>  1 file changed, 7 insertions(+)
>
> diff --git a/MAINTAINERS b/MAINTAINERS
> index 6dcfbd11efef..0119816d038d 100644
> --- a/MAINTAINERS
> +++ b/MAINTAINERS
> @@ -13641,6 +13641,13 @@ F:     include/linux/kfifo.h
>  F:     lib/kfifo.c
>  F:     samples/kfifo/
>
> +KFUZZTEST
> +M:  Ethan Graham <ethan.w.s.graham@gmail.com>
> +R:  Alexander Potapenko <glider@google.com>
> +F:  include/linux/kfuzztest.h
> +F:  lib/kfuzztest/
> +F:  Documentation/dev-tools/kfuzztest.rst

Please also add samples/kfuzztest here.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
AG_fn%3DVdRkSjvhO7wz7_PEznBOFgLjHCr2hSXwrKoO-hpMqTzg%40mail.gmail.com.
