Return-Path: <kasan-dev+bncBCP4ZTXNRIFBBL7NQX2QKGQETVEXXXQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13e.google.com (mail-lf1-x13e.google.com [IPv6:2a00:1450:4864:20::13e])
	by mail.lfdr.de (Postfix) with ESMTPS id E789F1B5A00
	for <lists+kasan-dev@lfdr.de>; Thu, 23 Apr 2020 13:06:23 +0200 (CEST)
Received: by mail-lf1-x13e.google.com with SMTP id t22sf2188126lfe.14
        for <lists+kasan-dev@lfdr.de>; Thu, 23 Apr 2020 04:06:23 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1587639983; cv=pass;
        d=google.com; s=arc-20160816;
        b=rMc6vg6hlDBGHEGYQOrxnIfMQz3JfIRN2bJRc9u1M+4X4shZoWTvuPT2K8HiJhwSh1
         4JmNk3Rpm1CaH4obNy4Rrs2EBBFkf/p5dkGVcXnytLIMLe5GBpGOVSHnDRN4qENnF67I
         8d/F95J6EDbBrvTkyByJseYmDd4MF7aXxmySUiYVqU4mshXXnarTtCOAqwTeuWgIEA6J
         QlgTiE0WsWPlbO14MszGslx4e+oo5C/i1Bym47fgIqpZPXyamR1tApefxcqeh5t3Ok/k
         N9gUA50u/iZc3qqV9NXg+cW5Re0A7ua43ddIOAYMh4IjktQ+hSIi+TPa2YjOd4RGDQAD
         lYuQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:message-id:from:cc:to:subject
         :mime-version:references:in-reply-to:user-agent:date:sender
         :dkim-signature;
        bh=FF6K+n65dqZBk1y4AynhqN9+2E1ro5mBGn2UJthgVJc=;
        b=o8ussr9XYvBpdsnystB2EU10S5EMOYk2f9jjyBRzOA3xL46S9w0PWT7oxLmNYJc2ls
         VdFmN7wtHc6jLOle7ea0GeUqCAcuWnywbpi6NBYjW+YCw3Oql0C0J1Vp576ac8PG3jkV
         JjlS/Ds9Kmnev3cYO5wxFgowuxRe0oMrvSs0pPD5aTyuFrkVlSYN89DAvVDIlyxIKegi
         eUtKTcAFrJ7FhZjtv+pwb44xREK+v2nvuaOMlRkBL2PtvmAIz6SU6Ja7RGryV3cGZdQL
         zZbic9dYFBbPkY0Wv8n+MWHYYlMYGwUxC+PQqNqcNJmcXaYj1YDcKnWC2F+ScmqvDU8U
         JSXw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@alien8.de header.s=dkim header.b=dSnLl3r5;
       spf=pass (google.com: domain of bp@alien8.de designates 5.9.137.197 as permitted sender) smtp.mailfrom=bp@alien8.de;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=alien8.de
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:user-agent:in-reply-to:references:mime-version:subject
         :to:cc:from:message-id:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=FF6K+n65dqZBk1y4AynhqN9+2E1ro5mBGn2UJthgVJc=;
        b=nz9STGJMOhmgoUUhxJMgG9tcfuDUoOwC8rijgWTpoKjshVzwnjkE+D/N+3YSW7LQ/D
         wBzubL+wxVtrW0OLMjt7utopSoeXg5Q9pIESUS8crbBpAi0oIE3tOGpURgZzpGbG2TCg
         gV8K+PlMgGXJY9KrhkNShS2BNCMqg1b1/eU+8cN4S+IBS58hkDgki+KbMMyVUWuf8PPE
         uyHrgwIYIQ0a5hw62kXDyWX7SH69FnmfPP2DG8tqyMeZxTKWer409wB+xI9ABWZdvngK
         /ezxmwekj4kmWZfXfw1qmFR0R82rUO4g5KdmuaXEUMMFI9gOMs4gUVfsE8qHa2BZMdSo
         bhSw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:user-agent:in-reply-to:references
         :mime-version:subject:to:cc:from:message-id:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=FF6K+n65dqZBk1y4AynhqN9+2E1ro5mBGn2UJthgVJc=;
        b=l7g74GOC1tbpWsSw7OaMptAgZSuvgNXDtAXav5V/mJY9y2yjhEgCaLV+JysLGXyros
         LwtGJmzWiWgVYEXwwLNEEnuT0cdwHgC3as0MuD8XvMwce2O1TUtpoQvFuJE9nSdNucH9
         93nc7agVXT0bsd/OBCUBAUicVDOZDcxhbAc83SDUes4+9haKwC/hZwYz/nNTfGwJn3ee
         FcZu2Srqe9kc6PmbUZ0A5GBCqjChjVsOamdKgES4UHUvUCUo7KMbwC+Wn2khTKVH+n87
         6rYHbxu9TE2lkIFvzPmKE209l1IDO0fmev7wp84VDQ3Sp4OcNyX9upqt7ptsqsoCOOjt
         4EZA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AGi0PuYGrvOivUFSmYzX1xr2WlyXeOQff9Fye9UqPhIMzGli80sQRURK
	kGzvw36MAy3bXQwbhD0QEtc=
X-Google-Smtp-Source: APiQypLbp5IzpWu4Yck2rvHAmszT8pNypTToKILRg3HeyJUbOs1sgrzXAXnApNSh2vOFbMUAV7s+wA==
X-Received: by 2002:ac2:4da7:: with SMTP id h7mr2016766lfe.95.1587639983415;
        Thu, 23 Apr 2020 04:06:23 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:9054:: with SMTP id n20ls1444733ljg.4.gmail; Thu, 23 Apr
 2020 04:06:22 -0700 (PDT)
X-Received: by 2002:a2e:9886:: with SMTP id b6mr2096133ljj.237.1587639982819;
        Thu, 23 Apr 2020 04:06:22 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1587639982; cv=none;
        d=google.com; s=arc-20160816;
        b=docFXwwtaglVspSiu/0Sc/Hpo4R126AJ8+6KvRjMM3THPt4y94lOneW65cjkxR8k7G
         pMXVRlCKFi9E779/wcAyqWY1X/yvK/WXrl1N/g3WWvdf+nCCDwIAcJcooVMbroj+BMtL
         NPbiJfa7q6H+hDIof81MnaEJXjQ2X8MujpKa9rZt6XKEqhkKpPZ+SJkZafpuMkCXhO5w
         VVfOY/vQ77m9ccTkPqu+Dbo+DiyPIKusMc+JS6moWbaNgFQXt+bkviMqi5aBc8pSLA0F
         JTXU1guru9BF/dzsBXdytFf5zeTp5mYKi7BMl/af9EfOrozRXrFxdbrOFUNQ4GbGuk3U
         Hnjw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=message-id:from:cc:to:subject:content-transfer-encoding
         :mime-version:references:in-reply-to:user-agent:date:dkim-signature;
        bh=o33zzbSEWrNleUhq11NCh6BFH/qH868Q9IHQ+H7NKhg=;
        b=k8KxDHjCr16DiUoKzWmTjkx4EQ8gtyUZHG8ptDz6JOIinj3w1JmRaZGZE+6Hi9wxuD
         g/bLEX4CDv97xmv24nIGQ7QPSM+dEI6xI1i89RBIvmYWY0e52+egRVmkJXNIzaohkUS9
         6xvMEPeJIIMTsHCFLZRVB3uaYe5zcm8MloY7MY8TtGfif6nZzy1T2dDQDHWJbtnRQ0UJ
         53hVem4w5lWjBXV1M+2ys4oIvUbwRl6T0Kv2PwCJATePn7CO+/vtQZEFQ4u2dhMziIF3
         v7fSF/xc5IdckLvWy4HvTNKXW4VJmt5fQKju8ip6DKZaU8rWXXECVL3DYMZXIi2gFY3u
         4wcg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@alien8.de header.s=dkim header.b=dSnLl3r5;
       spf=pass (google.com: domain of bp@alien8.de designates 5.9.137.197 as permitted sender) smtp.mailfrom=bp@alien8.de;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=alien8.de
Received: from mail.skyhub.de (mail.skyhub.de. [5.9.137.197])
        by gmr-mx.google.com with ESMTPS id f17si159938lfp.0.2020.04.23.04.06.22
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 23 Apr 2020 04:06:22 -0700 (PDT)
Received-SPF: pass (google.com: domain of bp@alien8.de designates 5.9.137.197 as permitted sender) client-ip=5.9.137.197;
Received: from [10.56.9.120] (x59cc8a78.dyn.telefonica.de [89.204.138.120])
	(using TLSv1.2 with cipher ECDHE-RSA-AES128-GCM-SHA256 (128/128 bits))
	(No client certificate requested)
	by mail.skyhub.de (SuperMail on ZX Spectrum 128k) with ESMTPSA id C91501EC0D7E;
	Thu, 23 Apr 2020 13:06:20 +0200 (CEST)
Date: Thu, 23 Apr 2020 13:06:19 +0200
User-Agent: K-9 Mail for Android
In-Reply-To: <838855E1-35B4-4235-B164-4C3ED127CCF4@lca.pw>
References: <20200423060825.GA9824@lst.de> <838855E1-35B4-4235-B164-4C3ED127CCF4@lca.pw>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Subject: Re: AMD boot woe due to "x86/mm: Cleanup pgprot_4k_2_large() and pgprot_large_2_4k()"
To: Qian Cai <cai@lca.pw>,Christoph Hellwig <hch@lst.de>
CC: "Peter Zijlstra (Intel)" <peterz@infradead.org>,x86 <x86@kernel.org>,LKML <linux-kernel@vger.kernel.org>,kasan-dev <kasan-dev@googlegroups.com>
From: Boris Petkov <bp@alien8.de>
Message-ID: <72CCEEC2-FF21-437C-873C-4C31640B2913@alien8.de>
X-Original-Sender: bp@alien8.de
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@alien8.de header.s=dkim header.b=dSnLl3r5;       spf=pass
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

On April 23, 2020 12:47:15 PM GMT+02:00, Qian Cai <cai@lca.pw> wrote:
>
>
>> On Apr 23, 2020, at 2:08 AM, Christoph Hellwig <hch@lst.de> wrote:
>> 
>> I can send one, but given that Qian found it and fixed it I'd have
>> to attribute it to him anyway :)
>> 
>> This assumes you don't want a complete resend of the series, of
>course.
>
>How about you send a single patch to include this and the the other
>pgprotval_t fix you mentioned early as well? Feel free to add my
>reported-by while all I care is to close out those bugs.

No need, I've rebased and testing. Stay tuned.


-- 
Sent from a small device: formatting sux and brevity is inevitable. 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/72CCEEC2-FF21-437C-873C-4C31640B2913%40alien8.de.
