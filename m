Return-Path: <kasan-dev+bncBCP4ZTXNRIFBBHX7QL2QKGQEDRVYSWQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23c.google.com (mail-lj1-x23c.google.com [IPv6:2a00:1450:4864:20::23c])
	by mail.lfdr.de (Postfix) with ESMTPS id C0FE91B4FCD
	for <lists+kasan-dev@lfdr.de>; Thu, 23 Apr 2020 00:05:18 +0200 (CEST)
Received: by mail-lj1-x23c.google.com with SMTP id e2sf623794ljp.11
        for <lists+kasan-dev@lfdr.de>; Wed, 22 Apr 2020 15:05:18 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1587593118; cv=pass;
        d=google.com; s=arc-20160816;
        b=T/M2LA4mrJ19MxjSGM5wIj8eA5OJ4/9mP+oDKLYzqOB0TYGll2HzoSkT130EU+X9qT
         aFGAJ+c3E6BlPy20c5uIAdO9ZRNcEpThnzqBHNTjBMG7VOm8KyTC7kr0ZtDxIZxGr8ur
         Yeq1r+fYlh7fpKHduybrXZ3okWIIx+0Ge/Egok+nSLk2hRVPDmdcA3B67KAcZ5D/gGKO
         hIcrYN3g/5beUoaRjri1LK1q7oGhWJCBVTZYRuy9vUrZsruZuU7UcYMR8/WJ8GmclFXx
         H7/4h6NxBoijjARqEEuRi9+m/2QWgl5txRvG8dYWBORudf2eRpnYaGeNLbQ7eUFqXuiI
         klqA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=Oy43ryNDo6rw2BQ7TZVFOhMYff+fIQVl/TIGq92xHiE=;
        b=VQZNw9DeSJgm6eSrgHRNIzJMeZyZNvTvvu05GgmGSfuAoFJ+AoBKso4zI/jSnnjONl
         YwXXBE+rMyfBaB6FuDi+btKPidMeEdiOyhH7bRkoAj+EzMskfhXtzjCnSWqL5ikKZEVB
         ilefR0UzfweeHJU9tBho/KVjYUcgYiOA+uJ+NAJUlmb71GU6JEUTlFVXUL5Eh9ODIWCo
         CmjsY0Z++CND7ZMpTfncgrQ/hgc3npDAKqg6KIqaaVdbBViJuMq1V3VnXrmWE65GdC5U
         li8SylPRayfJXIqnViknpeVPaS2t6LL9aX+ANvu2KnFnVCB8+L/9/Tx6nrb3b7G+oZui
         T/sQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@alien8.de header.s=dkim header.b=ocFtZn2S;
       spf=pass (google.com: domain of bp@alien8.de designates 5.9.137.197 as permitted sender) smtp.mailfrom=bp@alien8.de;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=alien8.de
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=Oy43ryNDo6rw2BQ7TZVFOhMYff+fIQVl/TIGq92xHiE=;
        b=UAg5Yd175uvxmLh3SiVL2mYhIUL2u+sEEl5J7eDo8p8n6Of8ROOU5Uc72G2RdC69yZ
         EKMqBgCH0prKZ8L5La1ad5xYp1iJa63n+IiHBs53QXhQTvJercEXdxEvXsehsiTmhuJ8
         uvjyU7SChB3s1xbNWo8Xtgi6c9ObY15bSvjXMfcY3/QSD3aQDVCEcGX2or+945J85Zht
         aOMtGRQJnp+F2BFwwHlo8MvaHt6EdSIQ2Dvtahlllakkp6B8Vbay1+H/GRsMnxf9k4Zb
         ZK8BAGsPjVJ9wUMAovILCvBe+a4LQ5kPJyErFaUAHyL34ySWQ2TpbRnYwhlDHYv1yKuU
         lEiw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=Oy43ryNDo6rw2BQ7TZVFOhMYff+fIQVl/TIGq92xHiE=;
        b=XKzGc/3l0RtlRwL/FvKjvXFCzB8jPWqpFh8vtR/VKjr7Lse6XoeiltTUouyQGKRJzD
         tTLvh8eIjeNxiYBdsFj8CahOs5vA3neai6CCoJUf+Je1RiC5H/mtMPRhkx0TLvKipBHl
         b5CLuPfJTtFiRBDndJ9u+GQ72yA/GGo8uW/54L//t4zCnqssLn1/c8F4IKceAOZN6Z4D
         OyfsVHzA2NEAkHU2qU8lhg6X6vTIjraf4O1J46hjPp40mgh3BiogWw6hn16j4eLyfDy/
         ttdsjaPyp16Bk0wJ6fkAGnAZya8w9TFDXBDiQVvm3KFLVvKYqwI9XI30tsBIyWjkxsNH
         AuXA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AGi0PuaFLgzc5JWWgtsS7+sHbERahKVHAqzPeT+llGbrkLoolwLNTqkU
	4rDFet1M+kq1YtdVCAHNmN0=
X-Google-Smtp-Source: APiQypKdOEzgmv1hpXcSnrAriqjubCJlZnDxYHakDLtmCnRGgoN6b3IjG9oL+r6wwl0nK+iJ5Cl3ug==
X-Received: by 2002:a2e:9490:: with SMTP id c16mr547037ljh.110.1587593118314;
        Wed, 22 Apr 2020 15:05:18 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a19:4a42:: with SMTP id x63ls886381lfa.7.gmail; Wed, 22 Apr
 2020 15:05:17 -0700 (PDT)
X-Received: by 2002:ac2:483a:: with SMTP id 26mr423724lft.5.1587593117801;
        Wed, 22 Apr 2020 15:05:17 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1587593117; cv=none;
        d=google.com; s=arc-20160816;
        b=K9s4swhl9qGpkkA/OxbHRobBS1VyX14/KNMhQEXj7SWts5I4Am8mNsy9jOb368y06t
         UySakfcx9paBcqF4aPntvJ4gi65oP9CF16usF8SSLn9zOR3b/ff+AQTWw877mfYwGTbl
         43rK+pDsYOIeOpKgBRyUJsKvc2LCN+f8rk0xLnOIwridT6mNzrC6yekpRSqAul06ru+u
         /J8VTAUg7F1COPcTRDa2Ov9/HwcBPTxPqOS2ff7gCXdBEgnNt5wJTRzJ+6PittTVOY1w
         WSQ7JBrQTcyMRC2VbqHuRYrkoWcDKUHqji+khULSEPCWYpt+vtGywYz7lJxmHO5IFrd0
         6Jfg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=hR0OWELozgYes+SCcKL8kMuliprtW69y8+TArTclptg=;
        b=u5Tj169QYfmfMRfkWsaR+0TcveFTMR/i8BkiUmuEzv2qWccluNXj4nGsU8hmPE4QOb
         DbMVkXTDTk/ByZkpG0lnnnlvqVVGCtbtvf6t1yHP67+Sb/ON1lkFHmme+XPfJDIbH+fs
         sqbs0VAAMJYrWzhKFm0Po8EBxIeJloaZfLcp/124cw5Z54YnLPO7PTNfCv3QMj2iE4eL
         OzT6mJ0Qr9J6WrCceJcbEu+8xePYdtnsnJzYd2Vx0Wm5mMGYBj2RdeQXLWycyif5CCB3
         Aa7dLdxw9WoMNexwp6hOOYJWnktyo0xvfUpH5LfM/pGQpE5ElS7/rAqrkeF2OSHB9+lB
         DqXw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@alien8.de header.s=dkim header.b=ocFtZn2S;
       spf=pass (google.com: domain of bp@alien8.de designates 5.9.137.197 as permitted sender) smtp.mailfrom=bp@alien8.de;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=alien8.de
Received: from mail.skyhub.de (mail.skyhub.de. [5.9.137.197])
        by gmr-mx.google.com with ESMTPS id f17si53652lfp.0.2020.04.22.15.05.17
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 22 Apr 2020 15:05:17 -0700 (PDT)
Received-SPF: pass (google.com: domain of bp@alien8.de designates 5.9.137.197 as permitted sender) client-ip=5.9.137.197;
Received: from zn.tnic (p200300EC2F0DC10034799E0EEF8349F9.dip0.t-ipconnect.de [IPv6:2003:ec:2f0d:c100:3479:9e0e:ef83:49f9])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by mail.skyhub.de (SuperMail on ZX Spectrum 128k) with ESMTPSA id 0981E1EC0D66;
	Thu, 23 Apr 2020 00:05:17 +0200 (CEST)
Date: Thu, 23 Apr 2020 00:05:12 +0200
From: Borislav Petkov <bp@alien8.de>
To: Qian Cai <cai@lca.pw>
Cc: Christoph Hellwig <hch@lst.de>,
	"Peter Zijlstra (Intel)" <peterz@infradead.org>,
	x86 <x86@kernel.org>, LKML <linux-kernel@vger.kernel.org>,
	kasan-dev <kasan-dev@googlegroups.com>
Subject: Re: AMD boot woe due to "x86/mm: Cleanup pgprot_4k_2_large() and
 pgprot_large_2_4k()"
Message-ID: <20200422220512.GK26846@zn.tnic>
References: <20200422214751.GJ26846@zn.tnic>
 <462564C5-1F0F-4635-AAB8-7629A6379425@lca.pw>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <462564C5-1F0F-4635-AAB8-7629A6379425@lca.pw>
User-Agent: Mutt/1.10.1 (2018-07-13)
X-Original-Sender: bp@alien8.de
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@alien8.de header.s=dkim header.b=ocFtZn2S;       spf=pass
 (google.com: domain of bp@alien8.de designates 5.9.137.197 as permitted
 sender) smtp.mailfrom=bp@alien8.de;       dmarc=pass (p=NONE sp=NONE
 dis=NONE) header.from=alien8.de
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

On Wed, Apr 22, 2020 at 05:57:09PM -0400, Qian Cai wrote:
> I thought Christ is going to send some minor updates anyway, so it may
> be better for him to include this one together? Otherwise, I am fine to
> send this one standalone.

You mean Christoph.

Ok, I'll let you guys hash it out.

Thx.

-- 
Regards/Gruss,
    Boris.

https://people.kernel.org/tglx/notes-about-netiquette

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200422220512.GK26846%40zn.tnic.
