Return-Path: <kasan-dev+bncBD2NJ5WGSUOBBJMZYOKAMGQEZIE4BMY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43f.google.com (mail-wr1-x43f.google.com [IPv6:2a00:1450:4864:20::43f])
	by mail.lfdr.de (Postfix) with ESMTPS id 4124A536329
	for <lists+kasan-dev@lfdr.de>; Fri, 27 May 2022 15:05:42 +0200 (CEST)
Received: by mail-wr1-x43f.google.com with SMTP id bt14-20020a056000080e00b002100d89c219sf751730wrb.2
        for <lists+kasan-dev@lfdr.de>; Fri, 27 May 2022 06:05:42 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1653656742; cv=pass;
        d=google.com; s=arc-20160816;
        b=wP1ekZ2UC8d4f9+bkc/FwDFo50ZtWWo+uQctyr4mLevvamxmItDcn4wOkEpIWyftPT
         iWF22dxceCBox5e3l6z0jEaK8ytNF+/cmuVJMJAkdpYI4MMeY7RvQvAS+mpO3ToGysFl
         6O8Va6lUtV87piLjhjgzW31DIDITAQRegyuiJYZSD4ujjOoxOFtV9k7aXPaoR6yBiWF9
         c3QJ3Jp7KVdp3WsrwwnCLudCiDcEUaKgwuXg4HmmgySiIa0wAEE47WgcbIkCfIJ+UMbJ
         jnHG1u+V4Ol0enMufw9rGUlVNM1w9/ROmOdsjOPZApzzReLilf2NdH93poJ6AYichzeN
         PmwA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:user-agent:references
         :in-reply-to:date:cc:to:from:subject:message-id:sender
         :dkim-signature;
        bh=3+CRtUT7PwtpYR7RgJU0iKH7piKfgwkNIhQuBQovS6A=;
        b=x9yi3vqxHm23Fzv57VpvPE3Bklo+QO5LjCGiDvWzFRXHaj72JDLCv4hHdddzQZB41c
         8VxFWPFxaK/ZOVrJQWTNziuVLu0TquA2GJA3uQd7mBieNbuuXGmViTqsV2WRY58d+Nrm
         M+9cA6eDWlIlHViud89ztp+RUszC5ir65VaVpKLR++ObcnMHcAZVmQ7TSh2V5TD+dE6S
         BcKaBZSVuPsx9ZXnXEPsTP6i9mUp0XQhfrhKAkrm/wV7lOxdoh3pmcB6QS6RHExsdlWx
         O49WwqaN5CjUiUO6kOnFE5KlcYaP2ffwkatsKrCMA2jzryCJruZSKJ8CtRfzp/Jw7vmj
         ziPQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@sipsolutions.net header.s=mail header.b=fSjes30Q;
       spf=pass (google.com: domain of johannes@sipsolutions.net designates 2a01:4f8:191:4433::2 as permitted sender) smtp.mailfrom=johannes@sipsolutions.net;
       dmarc=pass (p=NONE sp=REJECT dis=NONE) header.from=sipsolutions.net
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:message-id:subject:from:to:cc:date:in-reply-to:references
         :user-agent:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=3+CRtUT7PwtpYR7RgJU0iKH7piKfgwkNIhQuBQovS6A=;
        b=cSRGMi0qgiBZJE67p5FcPoHvyYwrUEO6Jy1I0ChBt2/zvr8da/Ipg9O5AedjX2grF0
         Y0+XrF7Kdyfjym2ZXIwY6n4x+o77HpyK7E4gtliNQt6E8n1ZOBoHtQcHL1po5R4f4lht
         WfhKS92Br/iH3NLpXZCWZHEoya8KMGhLfLClN59slXVfAW1Vjin/n+LfUkijBdsOT4eU
         nnAjSBKLTi1xHLxIAYnAL4fLLI4lExwlY9uHQ0NEHRHdA76GnYkRlwYHl966+Luau0Dq
         Ke2ymhRsVE6OQf2hRMypywqkyEyurSdLmoWLAxuQnIfmDVH8e9aClRhiTp+6EzM4Rbuk
         e94A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:message-id:subject:from:to:cc:date
         :in-reply-to:references:user-agent:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=3+CRtUT7PwtpYR7RgJU0iKH7piKfgwkNIhQuBQovS6A=;
        b=5D9I5HKkklyfkWQdsWkiP7L1983Eat9VWK4OppvO3GIjszdQ/ch8P6H8fI74Wtwgwn
         QVeUKeWKngZ+gunZ30VW35P42jK/pjNiV88Nuob2PzoFafaHRN2QBuGah9th5xRd75qz
         sFMRSG0aGrHNdyI12h8TtP/216XK2SscsTEUntmKuKZm6NIG/EHVwJNCdZNhDwPrL9nx
         M/J1Po/NnNgrZNeLSdTby8LQqvWniVa/wt8C+FzDP3XUAxqkpsBEEO8Jdl2abdcmL4e4
         JdWUSTNfIWXDfBrUc+rWoyVqKJDY5RXc909d/SphGjtL76RS72pe20Sva2ifczXWFv6z
         GZ8w==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530JNIjlURLC2lM340nBMNygSMt6JQHskQtKYAG/4JiFdf0Gnuyr
	5X+E39OFsVI7wjcPkqIqgX4=
X-Google-Smtp-Source: ABdhPJyoYfMjb2VCFQa/TXc1BvpDJLDCrFl3ndE+ddy5DWbCWVhL4wfYvwvQDm2K77oOGCefdGWQqQ==
X-Received: by 2002:a5d:6c61:0:b0:20f:ef37:a9d0 with SMTP id r1-20020a5d6c61000000b0020fef37a9d0mr15630732wrz.140.1653656741616;
        Fri, 27 May 2022 06:05:41 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6000:1e0b:b0:20e:7a8a:8c81 with SMTP id
 bj11-20020a0560001e0b00b0020e7a8a8c81ls31408175wrb.1.gmail; Fri, 27 May 2022
 06:05:40 -0700 (PDT)
X-Received: by 2002:adf:e2cb:0:b0:20c:c1bb:9fcb with SMTP id d11-20020adfe2cb000000b0020cc1bb9fcbmr35074927wrj.35.1653656740520;
        Fri, 27 May 2022 06:05:40 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1653656740; cv=none;
        d=google.com; s=arc-20160816;
        b=HoBDKQBpO1+m2Ce+o81diDJkysfD6J0xLR6wDO0YoBaVq5zNNmte74sAsZDD+7ulwa
         Z2Tuiu5kZe1/GOcSo7qpp6uBLim/nvEkPr80CnDyBS4v4hPxGTpe6MjeVh6z78Jiu8eP
         +Iw0CwIfP9QHY0l7zo0e5EPk3X0PPlMLBNB+3doYXyoT1W3JMSJ+rPVRCtwc/WKKNwX0
         seMh5ft33yEpk6idwR/ymQS60UpmQMmWfFzj+3t92GL0yVZxQb0JSL5MmJiY1TwK2CQY
         AHhXwW66fosCm5O3LFMvywGTIEgT/Uj/uA/9YxM/yYpJgLy3wCqC3LLATAuCcg1wX0Zx
         wWKA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:user-agent:content-transfer-encoding:references
         :in-reply-to:date:cc:to:from:subject:message-id:dkim-signature;
        bh=pglHjp1be88ovPoKqF2KdA8KHzjD+SK0osh4u3fcrwM=;
        b=JPbPXyX34HUpgoyl13KcaEilXaJrwUt/hJDX/cRrmsOriqJaxq6tKS7uxvjzL+uhR3
         fAuErj83MGABt11gmcO741O8jFlWOYOXaGstKEX+3NSA/sPzwiPXx4RvVgwl+/q6xpzl
         rpo8aaHvwIoB5F96hzVsOttbjqa43fLeojZGSspYL1q1T/zrJ5VV0aUGghpETpkbyvyC
         m/Ik4MlQc9oTJ//KJonxdF+8FzG9d+ekKqoQcoawutUlQXNBHgGMewoxJmibQcstLveJ
         65C/Jjw48PFoOy335p95PudES5PXDwP0HPoo0jf1vBO3Y0lwDIaurOUCtQ44uC/vceyA
         VbSA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@sipsolutions.net header.s=mail header.b=fSjes30Q;
       spf=pass (google.com: domain of johannes@sipsolutions.net designates 2a01:4f8:191:4433::2 as permitted sender) smtp.mailfrom=johannes@sipsolutions.net;
       dmarc=pass (p=NONE sp=REJECT dis=NONE) header.from=sipsolutions.net
Received: from sipsolutions.net (s3.sipsolutions.net. [2a01:4f8:191:4433::2])
        by gmr-mx.google.com with ESMTPS id n189-20020a1ca4c6000000b00393e80e70c9si77691wme.1.2022.05.27.06.05.40
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 27 May 2022 06:05:40 -0700 (PDT)
Received-SPF: pass (google.com: domain of johannes@sipsolutions.net designates 2a01:4f8:191:4433::2 as permitted sender) client-ip=2a01:4f8:191:4433::2;
Received: by sipsolutions.net with esmtpsa (TLS1.3:ECDHE_X25519__RSA_PSS_RSAE_SHA256__AES_256_GCM:256)
	(Exim 4.95)
	(envelope-from <johannes@sipsolutions.net>)
	id 1nuZeq-00636Z-PL;
	Fri, 27 May 2022 15:05:36 +0200
Message-ID: <e2339dcea553f9121f2d3aad29f7428c2060f25f.camel@sipsolutions.net>
Subject: Re: [RFC PATCH v3] UML: add support for KASAN under x86_64
From: Johannes Berg <johannes@sipsolutions.net>
To: David Gow <davidgow@google.com>, Vincent Whitchurch
 <vincent.whitchurch@axis.com>, Patricia Alfonso <trishalfonso@google.com>, 
 Jeff Dike <jdike@addtoit.com>, Richard Weinberger <richard@nod.at>,
 anton.ivanov@cambridgegreys.com,  Dmitry Vyukov <dvyukov@google.com>,
 Brendan Higgins <brendanhiggins@google.com>
Cc: kasan-dev <kasan-dev@googlegroups.com>, linux-um@lists.infradead.org,
 LKML <linux-kernel@vger.kernel.org>, Daniel Latypov <dlatypov@google.com>
Date: Fri, 27 May 2022 15:05:35 +0200
In-Reply-To: <20220526010111.755166-1-davidgow@google.com>
References: <20220525111756.GA15955@axis.com>
	 <20220526010111.755166-1-davidgow@google.com>
Content-Type: text/plain; charset="UTF-8"
User-Agent: Evolution 3.44.1 (3.44.1-1.fc36)
MIME-Version: 1.0
X-malware-bazaar: not-scanned
X-Original-Sender: johannes@sipsolutions.net
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@sipsolutions.net header.s=mail header.b=fSjes30Q;       spf=pass
 (google.com: domain of johannes@sipsolutions.net designates
 2a01:4f8:191:4433::2 as permitted sender) smtp.mailfrom=johannes@sipsolutions.net;
       dmarc=pass (p=NONE sp=REJECT dis=NONE) header.from=sipsolutions.net
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

On Wed, 2022-05-25 at 18:01 -0700, David Gow wrote:
> From: Patricia Alfonso <trishalfonso@google.com>
> 
> Make KASAN run on User Mode Linux on x86_64.

FWIW, I just added this to my virtual lab which I use as CI tests, and
it immediately found a use-after-free bug in mac80211!

I did note (this is more for kasan-dev@) that the "freed by" is fairly
much useless when using kfree_rcu(), it might be worthwhile to annotate
that somehow, so the stack trace is recorded by kfree_rcu() already,
rather than just showing the RCU callback used for that.

johannes

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/e2339dcea553f9121f2d3aad29f7428c2060f25f.camel%40sipsolutions.net.
