Return-Path: <kasan-dev+bncBDVIHK4E4ILBBOEOZXWAKGQEBX5TMPI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x339.google.com (mail-wm1-x339.google.com [IPv6:2a00:1450:4864:20::339])
	by mail.lfdr.de (Postfix) with ESMTPS id 228B0C343B
	for <lists+kasan-dev@lfdr.de>; Tue,  1 Oct 2019 14:31:53 +0200 (CEST)
Received: by mail-wm1-x339.google.com with SMTP id z205sf1342256wmb.7
        for <lists+kasan-dev@lfdr.de>; Tue, 01 Oct 2019 05:31:53 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1569933112; cv=pass;
        d=google.com; s=arc-20160816;
        b=Zc4MzVv/YShFR5E499wK32V+q7i8ajs8eeexVjd94ZNH/19OXypMd6OOpECDCThrfD
         kASeH7Bh2LvokoilJ3qjlK7bi1W4aspx3SS5+KB79Ouu9aavApxxDNj/XKv0IDtrqzMC
         IwLJkT3C4nkXJuLcxrLvBkQGyaOyVFLMjuasP4dk6765s/WCf6eyOWRalFDbFdrAIfTB
         hh1jMbP1USN5oZPSquXl89S8EvagKjLfas9tIBBbFM4Jmpx23b1C+8vPrtyYQdhw+7HQ
         Uqpwz2OIc7UIrkDeF98yDLvn7HbJuvxXe2Ib8H/Twrt2QnjRYH4B2cFL123Xqr25iwKK
         0Lxw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=GMRx2YTxT/Tn1RHukQlrHiUmFmDO3o4R+1/Jf9vK1kU=;
        b=jOZ8m/mFc0Z/ZdwPi0wLkTr0MJ7+Fz1KlJ/FARZmeWIgaDCcNZbnNNO6P6QUsyZB29
         DyvJbk1GEvc/+kuztaoWli3AMx69nr3J+XvOCPdTl6W2dUpLBkp7uFux3WuXr6zcr476
         dEyzlGL5ms2w2O0Ygm1g4nUzme+xQBgqs6PkrCoDOwlGuSb1MDdERh91DS6fZPQ2K89L
         QbuF2+mizl7+hCIjIwP8CI7ao+toAUPH1Lqyk+yfgpPYDGf1yfHqpZYy3Dqn+C6b6uR+
         w3QzkPVB8Fxng+Ebkcamywrrg3dd3cHg5xD6L74YJeUPKTHfcpNvmQW+L1Eo5vwPwwWt
         pQLw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@shutemov-name.20150623.gappssmtp.com header.s=20150623 header.b=nTBOO2eh;
       spf=neutral (google.com: 2a00:1450:4864:20::542 is neither permitted nor denied by best guess record for domain of kirill@shutemov.name) smtp.mailfrom=kirill@shutemov.name
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:content-transfer-encoding:in-reply-to
         :user-agent:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=GMRx2YTxT/Tn1RHukQlrHiUmFmDO3o4R+1/Jf9vK1kU=;
        b=JHV/S2wBzKoPwT0Eq6nXk8JvXpHtfP+7jZxQxnXjBqt6avh58q+3mhJ3Tw/BteNRwF
         4zE1BZEnzLfKT320nul38HuaYYfpcii4cx2GpyXH8+bIJb4sBjEgALhweqjhuXr7HKGW
         FeMePrtWUa1WQIZywggkMtO3I5iTDmHY5IgBe+OgBIzOI2mX319aZBhmeaiiUGqPSXu3
         qsqURtnvevcKHyfbiSB8gDUm5XQWOl9M5qiABQDPH8io8ojyBfQxwkrvwv2xYCaTR3La
         mO1SJMYnDqNNeTdn2nDGiTnfq0PClPUFPDYg/CgCH9c1gfSJoF2ZJahyAJrTJIRKwy32
         RmPg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition
         :content-transfer-encoding:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=GMRx2YTxT/Tn1RHukQlrHiUmFmDO3o4R+1/Jf9vK1kU=;
        b=alp+S54+FFetfoBLMukOCiLou49chZJnp4JzMmNFPmJA78M0K+qKoGmr+b86BAcrqH
         WVX0zQdu+r6fpOOhyxmcod2xrrGD1nRLmWfMt7+7uba6bUys5mMRCOXyWNEZ8x+OcaKb
         6Vo9NpPkE2F3uUX02PHiivghYL0SRtZlyexBVMa+pcAgLLfipFikIuzdU4AlzlTHYfIX
         sDLZNmdkaYcgctVgBJQ07pRCrXbMxzZ/ktBk6Xr7XV4tkBi6BmLTsJGhUVtulqctClGD
         YqNbJ3YJtIscMHp4UJA+KGcA30Gls11JvOzlgaV9KftIT5bTAUdHm9OuJjdrxRq/4eCT
         GOyw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAWauSvbq5KuAYvpIPiiof8fPjfilz2e6xssuuoSo367AkZeT8ST
	KJ7imaFoIisLN/SS8cJBlds=
X-Google-Smtp-Source: APXvYqxvWZz03/OMFvHykf7H3YsEkpVMa5FiR7Q3dfw7l4QqutxtaJxbIefWLvko+TvbqG5H4JSFYQ==
X-Received: by 2002:a5d:4803:: with SMTP id l3mr18888924wrq.301.1569933112728;
        Tue, 01 Oct 2019 05:31:52 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1c:9dc8:: with SMTP id g191ls1120699wme.2.gmail; Tue, 01
 Oct 2019 05:31:52 -0700 (PDT)
X-Received: by 2002:a1c:cbcc:: with SMTP id b195mr3790055wmg.80.1569933112205;
        Tue, 01 Oct 2019 05:31:52 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1569933112; cv=none;
        d=google.com; s=arc-20160816;
        b=alaQorQ3rfI7t8WiFemC5KvDDz381kCfVWWPT0jGLJkw+9z4fsejZ/gQ663J90J/qa
         FeEPPrziYxFGzpn3A6JvJbM7WOHyuB4DjEPo0P/c6nYnYJhoZwAx/vPY77qiGcVSNKtR
         BbY8GhVxecGRljWZcCipwLaqY0E2qld9+/XtSZEzGD2dELuwjS4MhnxELTUkqwq8YPVV
         1z3mbfYFpj775YBUJX4pW1R/8XqO5IlG8hNNQ1z9eMttwuzUzFMFPXaF4hl7PN5Q63vu
         5arO9OTduYJeDqZBh2Y+/IbxlxyFJqog9q9M1mripZYVsxIrrNMOKTp1s7g4k7+kEN2+
         0Zkg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-transfer-encoding
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=+oZPiXvOUSLu8pkEA5SDtoDi+xBvTxdx9cy3tZSs02c=;
        b=lxuvwuGAF0rKBu6+pkDoLrJyVGFfCjdts7y0+FONzglKli2kZS1KCpAHP/jkY846mZ
         NgIiI4TU0yfshi2z/xgt1V4DtA5crqDw+exYhggxNxl7iBGKrenXpTlUpqPXUfUFQjEc
         HQn2xEJ8LsmEu9UDm7MnGZY/1vz8f2/ltWA9h5Q/EffOwp+UIGaKXqsM+jhuUZkQwkhE
         7YAOFPbQGOl219IfN5VRBW1o23Vuv7btNzH+Qa70JFR36TicwanwdFAn6+uImgOzyp7u
         k1IwUDCuoWMnnuEID8IqLZwI+ueSgafXyAP0lhRCu6HniIaSnC601RO5hLGF9Px0TA5v
         WDqA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@shutemov-name.20150623.gappssmtp.com header.s=20150623 header.b=nTBOO2eh;
       spf=neutral (google.com: 2a00:1450:4864:20::542 is neither permitted nor denied by best guess record for domain of kirill@shutemov.name) smtp.mailfrom=kirill@shutemov.name
Received: from mail-ed1-x542.google.com (mail-ed1-x542.google.com. [2a00:1450:4864:20::542])
        by gmr-mx.google.com with ESMTPS id q185si215344wme.1.2019.10.01.05.31.52
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 01 Oct 2019 05:31:52 -0700 (PDT)
Received-SPF: neutral (google.com: 2a00:1450:4864:20::542 is neither permitted nor denied by best guess record for domain of kirill@shutemov.name) client-ip=2a00:1450:4864:20::542;
Received: by mail-ed1-x542.google.com with SMTP id y91so11696563ede.9
        for <kasan-dev@googlegroups.com>; Tue, 01 Oct 2019 05:31:52 -0700 (PDT)
X-Received: by 2002:a17:907:20c4:: with SMTP id qq4mr24003067ejb.161.1569933111868;
        Tue, 01 Oct 2019 05:31:51 -0700 (PDT)
Received: from box.localdomain ([86.57.175.117])
        by smtp.gmail.com with ESMTPSA id ot24sm1833844ejb.59.2019.10.01.05.31.51
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 01 Oct 2019 05:31:51 -0700 (PDT)
Received: by box.localdomain (Postfix, from userid 1000)
	id BCA03102FB8; Tue,  1 Oct 2019 15:31:51 +0300 (+03)
Date: Tue, 1 Oct 2019 15:31:51 +0300
From: "Kirill A. Shutemov" <kirill@shutemov.name>
To: Qian Cai <cai@lca.pw>
Cc: Vlastimil Babka <vbabka@suse.cz>,
	Andrew Morton <akpm@linux-foundation.org>, linux-mm@kvack.org,
	linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com,
	"Kirill A. Shutemov" <kirill.shutemov@linux.intel.com>,
	Matthew Wilcox <willy@infradead.org>,
	Mel Gorman <mgorman@techsingularity.net>,
	Michal Hocko <mhocko@kernel.org>,
	Dmitry Vyukov <dvyukov@google.com>,
	Walter Wu <walter-zh.wu@mediatek.com>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>
Subject: Re: [PATCH v2 2/3] mm, page_owner: decouple freeing stack trace from
 debug_pagealloc
Message-ID: <20191001123151.qmv4ist3enq65uha@box>
References: <eccee04f-a56e-6f6f-01c6-e94d94bba4c5@suse.cz>
 <731C4866-DF28-4C96-8EEE-5F22359501FE@lca.pw>
 <218f6fa7-a91e-4630-12ea-52abb6762d55@suse.cz>
 <20191001115114.gnala74q3ydreuii@box>
 <1569932788.5576.247.camel@lca.pw>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <1569932788.5576.247.camel@lca.pw>
User-Agent: NeoMutt/20180716
X-Original-Sender: kirill@shutemov.name
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@shutemov-name.20150623.gappssmtp.com header.s=20150623
 header.b=nTBOO2eh;       spf=neutral (google.com: 2a00:1450:4864:20::542 is
 neither permitted nor denied by best guess record for domain of
 kirill@shutemov.name) smtp.mailfrom=kirill@shutemov.name
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

On Tue, Oct 01, 2019 at 08:26:28AM -0400, Qian Cai wrote:
> On Tue, 2019-10-01 at 14:51 +0300, Kirill A. Shutemov wrote:
> > On Tue, Oct 01, 2019 at 10:07:44AM +0200, Vlastimil Babka wrote:
> > > On 10/1/19 1:49 AM, Qian Cai wrote:
> > > >=20
> > > >=20
> > > > > On Sep 30, 2019, at 5:43 PM, Vlastimil Babka <vbabka@suse.cz> wro=
te:
> > > > >=20
> > > > > Well, my use case is shipping production kernels with CONFIG_PAGE=
_OWNER
> > > > > and CONFIG_DEBUG_PAGEALLOC enabled, and instructing users to boot=
-time
> > > > > enable only for troubleshooting a crash or memory leak, without a=
 need
> > > > > to install a debug kernel. Things like static keys and page_ext
> > > > > allocations makes this possible without CPU and memory overhead w=
hen not
> > > > > boot-time enabled. I don't know too much about KASAN internals, b=
ut I
> > > > > assume it's not possible to use it that way on production kernels=
 yet?
> > > >=20
> > > > In that case, why can=E2=80=99t users just simply enable page_owner=
=3Don and
> > > > debug_pagealloc=3Don for troubleshooting? The later makes the kerne=
l
> > > > slower, but I am not sure if it is worth optimization by adding a n=
ew
> > > > parameter. There have already been quite a few MM-related kernel
> > > > parameters that could tidy up a bit in the future.
> > >=20
> > > They can do that and it was intention, yes. The extra parameter was
> > > requested by Kirill, so I'll defer the answer to him :)
> >=20
> > DEBUG_PAGEALLOC is much more intrusive debug option. Not all architectu=
res
> > support it in an efficient way. Some require hibernation.
> >=20
> > I don't see a reason to tie these two option together.
>=20
> Make sense. How about page_owner=3Don will have page_owner_free=3Don by d=
efault?
> That way we don't need the extra parameter.

It's 0.1% of system memory. Does it matter for a debug option? I don't know=
.

--=20
 Kirill A. Shutemov

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/20191001123151.qmv4ist3enq65uha%40box.
