Return-Path: <kasan-dev+bncBAABBWET4LYAKGQECA6GIAA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3b.google.com (mail-yb1-xb3b.google.com [IPv6:2607:f8b0:4864:20::b3b])
	by mail.lfdr.de (Postfix) with ESMTPS id 37693136F4D
	for <lists+kasan-dev@lfdr.de>; Fri, 10 Jan 2020 15:27:37 +0100 (CET)
Received: by mail-yb1-xb3b.google.com with SMTP id z3sf1610390ybg.9
        for <lists+kasan-dev@lfdr.de>; Fri, 10 Jan 2020 06:27:37 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1578666456; cv=pass;
        d=google.com; s=arc-20160816;
        b=GhOUj3LxI9j99vD74BRK9DTGVVFvwgnNvzuJOs+rciF1MSNltNPL5iylyPAj37a2qv
         +EJtQ18b6hJ5y8DBDBnmc15JUGK1rK/PNp5UurLIVE04EHSjotbH3B/KsGs+mMA9nP1p
         ALJK4bNrDNCXwvigH/LzJNPyxnCxSz+n5cKjrisEb+qBqj3E6vLzxBMp4DlGnO0n7DCh
         H3uq5BN1eyG5iGPqCd1+DZOI3toTb+wCGh/l87TbhriCM9pW7+IGfbSWLIC/NA19cdz4
         HIVH1VOdDDLkArokCX7pC0ZNvZk3AbxFmA56zJ1smBfGj4nZaKO7poafI+5tD6IxCS3S
         xxdA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :mime-version:user-agent:date:message-id:autocrypt:from:references
         :cc:to:subject:ironport-sdr:sender:dkim-signature;
        bh=D0fO3D342pcKNZdAOBUiQ5jmA8Yf10n/pwrTpdaNJds=;
        b=ekwZpGaV6NS/67K5MA8x4b4TlMwjZa9XtClYbp1P2nvW2GDCKv3af4WwLdUlHikhRs
         5qvFXifik6tXnb8ze1Altpf3mCg0GrL/+CNHlHCBBBHSrZEXWJjgxeAWsfiFUYlpfenW
         UJGBC4az7jGczAKMahNtth4sYnjaRpd6uo5YQGvZYaOHXP8vrnbOf4EhWRLuOsg4fI2w
         9QoUanauYZAba0s9MyhTxYXwWKOdT0Z2C9mOqHmEGavV0TW1K+YpyrVYL4ijqZaCTAik
         71c3NQJPUn9Pua1fMJWH8W6Shxn9Rq7qzJGtQlUT2jK0O3affUAUPwYvCNQvxgAHgI7Y
         ce5g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@citrix.com header.s=securemail header.b="eB8G/GAn";
       spf=pass (google.com: domain of sergey.dyasli@citrix.com designates 216.71.145.155 as permitted sender) smtp.mailfrom=sergey.dyasli@citrix.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=citrix.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:ironport-sdr:subject:to:cc:references:from:autocrypt
         :message-id:date:user-agent:mime-version:in-reply-to
         :content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=D0fO3D342pcKNZdAOBUiQ5jmA8Yf10n/pwrTpdaNJds=;
        b=UvlZfkkADNQdZtSZq9Buh+TZF5d7niwhk1aCxGPjnmLM9HA0ln+qh2w7dELYKIsG/8
         f9s72A70cjXKsXTTKb+mr6+ah3IiACDT2EDK9TyawjATHQ+GDzsbU3QJ3LKUUM7ho5Mr
         X7mTnxwjd0iSMFCSuIAferTddvaHmuPTOZojh5c8m6gX458iWwfg5u45/sCDA87Nqvdo
         +v+TK47+jZu364nVRbGN93utQ2XWa4FuN+K8jguVfigH9am2Qd1cixhDnCv7MwDkXSuK
         LVL6pcQQrWyzyY/WNYi+faBbiFuoSlNqqsl6ER0YqmIIoUW6Q753G9Z5PNaWsaxUdWsT
         9t+Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:ironport-sdr:subject:to:cc:references
         :from:autocrypt:message-id:date:user-agent:mime-version:in-reply-to
         :content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=D0fO3D342pcKNZdAOBUiQ5jmA8Yf10n/pwrTpdaNJds=;
        b=RpE6W4TvO8f2zG/9rn2awL1XuFS1uGDuY1f+ESKhRcb2xxtjFk531xPfJjN/iLUK3a
         U/nUCaWKKmopj4b+FYPmhPN6AWqfeQJEenzsZ95nbZE46ehazwonNeIYJcD9X9KhPPLe
         DuCeEHGyecpoSCg3gtUPY7T2uVES+CHbJML8Smm1f3HJ6rLkaPXipeeAFca6VQEBcGPE
         rNt3YLXY531dujYI0JSlSAbM3426dUto7sA2fveHMpxr7DYJn5RrRYIJsrGY2CDri/CW
         vCtETDn2JTRJM/2ImIPCxwy8iIY+XNWN/zOmLMvP7ISFW1dBd/bsQV9iuoZo3ZYATF4/
         3Ipw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAVRmvyhbCP1H4CgjLuYXLJvVGdbS1J7JZsad6xKCljKeAeiEL3N
	rCG/xRLUSdtpaG47rDNtvG4=
X-Google-Smtp-Source: APXvYqwMG5zuxS9S1iqABFdBULxybCm5CCTQbwcW3IrO6rfSGNxtr5Wl4sIVvysWOgUSEqf6xW0Jqw==
X-Received: by 2002:a0d:e111:: with SMTP id k17mr2994003ywe.50.1578666456196;
        Fri, 10 Jan 2020 06:27:36 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:cacb:: with SMTP id a194ls832234ybg.13.gmail; Fri, 10
 Jan 2020 06:27:35 -0800 (PST)
X-Received: by 2002:a25:9c41:: with SMTP id x1mr2740635ybo.344.1578666455789;
        Fri, 10 Jan 2020 06:27:35 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1578666455; cv=none;
        d=google.com; s=arc-20160816;
        b=A6cAwdbzBvwejakSSWX2YqZ7s/bavosLS//tC7vLLo3+RV0J3XsexFzboTtznPCWIR
         gqkbduLzsTnEhp0mKrUDvfqYibkTYEXRdjhBJ4dIyTMo+T4m/H5WT3k6vnN/6poPuATD
         G4OBASIErnNFTnDA5FgXChTvP5LSe4HsTiUoQ3e/cVesVwGbW3rzVs900NuPDf7IgMBB
         V6qRA71trcf2v9TNBcMCDlx2k8+646Adq3lJipMbE3Mz6TwKDaBPOYXYyGJ/l6JcmWfo
         jzMfL+KQudawfFc18FsdIzHwiKOveNh9DGlYlxm+HgrUk+F/w1Sly1Dnc82OdN1zju5I
         z6Jg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:autocrypt:from:references:cc:to:subject
         :ironport-sdr:dkim-signature;
        bh=oqlcxDrVVKABFTXB0PVcwHJAiv9YGfWbqOqK+vhLhlw=;
        b=ageouhAVliTJXSmCq6M3H6GB7Lu6ID6rjzrDnJQKXiPjhJAEHWwjHFVWcP8vS0E3n2
         +1W7hNnRl+IOVL6Aw71eJn8kx4eu1P+3VtQlkngmeEhwwBU/WrYV77dw63yIszBmBb8g
         mIkxc9xkyKm7WrnW80NumFfcaVH0DegwEQeoZrWJWD2C6Oud5GJQefOpR76u+7F0YWz6
         8kHFKtTjervk01X6VkmLlz7UsIWYmiu5XWuRLOPKKO5MES/1SGlUrYbgGcYWeFwWiCIK
         HNOUXXqujrcvVnjU6mN06b4gvh5p3I+pqFmam7fBlG4CRK8cZKRSQS7FhfmnZdty3UKz
         4Trw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@citrix.com header.s=securemail header.b="eB8G/GAn";
       spf=pass (google.com: domain of sergey.dyasli@citrix.com designates 216.71.145.155 as permitted sender) smtp.mailfrom=sergey.dyasli@citrix.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=citrix.com
Received: from esa3.hc3370-68.iphmx.com (esa3.hc3370-68.iphmx.com. [216.71.145.155])
        by gmr-mx.google.com with ESMTPS id p136si93178ybc.4.2020.01.10.06.27.35
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 10 Jan 2020 06:27:35 -0800 (PST)
Received-SPF: pass (google.com: domain of sergey.dyasli@citrix.com designates 216.71.145.155 as permitted sender) client-ip=216.71.145.155;
Received-SPF: None (esa3.hc3370-68.iphmx.com: no sender
  authenticity information available from domain of
  sergey.dyasli@citrix.com) identity=pra;
  client-ip=162.221.158.21; receiver=esa3.hc3370-68.iphmx.com;
  envelope-from="sergey.dyasli@citrix.com";
  x-sender="sergey.dyasli@citrix.com";
  x-conformance=sidf_compatible
Received-SPF: Pass (esa3.hc3370-68.iphmx.com: domain of
  sergey.dyasli@citrix.com designates 162.221.158.21 as
  permitted sender) identity=mailfrom;
  client-ip=162.221.158.21; receiver=esa3.hc3370-68.iphmx.com;
  envelope-from="sergey.dyasli@citrix.com";
  x-sender="sergey.dyasli@citrix.com";
  x-conformance=sidf_compatible; x-record-type="v=spf1";
  x-record-text="v=spf1 ip4:209.167.231.154 ip4:178.63.86.133
  ip4:195.66.111.40/30 ip4:85.115.9.32/28 ip4:199.102.83.4
  ip4:192.28.146.160 ip4:192.28.146.107 ip4:216.52.6.88
  ip4:216.52.6.188 ip4:162.221.158.21 ip4:162.221.156.83
  ip4:168.245.78.127 ~all"
Received-SPF: None (esa3.hc3370-68.iphmx.com: no sender
  authenticity information available from domain of
  postmaster@mail.citrix.com) identity=helo;
  client-ip=162.221.158.21; receiver=esa3.hc3370-68.iphmx.com;
  envelope-from="sergey.dyasli@citrix.com";
  x-sender="postmaster@mail.citrix.com";
  x-conformance=sidf_compatible
IronPort-SDR: n2x5OQV5+wxwJ/OY1mimcnkZJ4ZpHwMNQu/14G8v3Nz7/CTkOmZneD7S6JZIy2Fs9J6dXNq4hs
 yPzA2Zm7H+pQoylj4XyFgwnW0TfrJI+k2UCJ3WS4k4sw1IZTSJUOcnMZTLbw9+E6lJGTpVE7xk
 WuKkpUnrUHoYqEJz0JCDjkfaqbjXpIGD2I0Jhf+2Lb/MNn+sFXjQ8rxlAMLzd8JUR1uGo6cckd
 GYXX7QJ/w44r6HuQ5nrtWeUqy7pC7kQM5eKBp2NL2W6ER5LlkqHw+xm7tuw1gQTNwfZEicNGmm
 b28=
X-SBRS: 2.7
X-MesageID: 10727982
X-Ironport-Server: esa3.hc3370-68.iphmx.com
X-Remote-IP: 162.221.158.21
X-Policy: $RELAYED
X-IronPort-AV: E=Sophos;i="5.69,417,1571716800"; 
   d="scan'208";a="10727982"
Subject: Re: [PATCH v1 4/4] xen/netback: Fix grant copy across page boundary
 with KASAN
To: Paul Durrant <pdurrant@gmail.com>
CC: <xen-devel@lists.xen.org>, <kasan-dev@googlegroups.com>,
	<linux-mm@kvack.org>, <linux-kernel@vger.kernel.org>, Andrey Ryabinin
	<aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>, "Dmitry
 Vyukov" <dvyukov@google.com>, Boris Ostrovsky <boris.ostrovsky@oracle.com>,
	Juergen Gross <jgross@suse.com>, Stefano Stabellini <sstabellini@kernel.org>,
	George Dunlap <george.dunlap@citrix.com>, Ross Lagerwall
	<ross.lagerwall@citrix.com>, Andrew Morton <akpm@linux-foundation.org>, "Wei
 Liu" <wei.liu@kernel.org>, "sergey.dyasli@citrix.com >> Sergey Dyasli"
	<sergey.dyasli@citrix.com>
References: <20200108152100.7630-1-sergey.dyasli@citrix.com>
 <20200108152100.7630-5-sergey.dyasli@citrix.com>
 <CACCGGhCGcdEq7CC3J0201ETvAd+PZ2fTDNUS3mo599Tuf-61yA@mail.gmail.com>
From: Sergey Dyasli <sergey.dyasli@citrix.com>
Autocrypt: addr=sergey.dyasli@citrix.com; keydata=
 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
Message-ID: <dc322a8f-d0ae-dea6-4fe0-cc4d5d14f4d4@citrix.com>
Date: Fri, 10 Jan 2020 14:27:30 +0000
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101
 Thunderbird/68.2.2
MIME-Version: 1.0
In-Reply-To: <CACCGGhCGcdEq7CC3J0201ETvAd+PZ2fTDNUS3mo599Tuf-61yA@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"
Content-Language: en-US
X-Original-Sender: sergey.dyasli@citrix.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@citrix.com header.s=securemail header.b="eB8G/GAn";       spf=pass
 (google.com: domain of sergey.dyasli@citrix.com designates 216.71.145.155 as
 permitted sender) smtp.mailfrom=sergey.dyasli@citrix.com;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=citrix.com
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

On 09/01/2020 13:36, Paul Durrant wrote:
> On Wed, 8 Jan 2020 at 15:21, Sergey Dyasli <sergey.dyasli@citrix.com> wrote:
>>
>> From: Ross Lagerwall <ross.lagerwall@citrix.com>
>>
>> When KASAN (or SLUB_DEBUG) is turned on, the normal expectation that
>> allocations are aligned to the next power of 2 of the size does not
>> hold. Therefore, handle grant copies that cross page boundaries.
>>
>> Signed-off-by: Ross Lagerwall <ross.lagerwall@citrix.com>
>> Signed-off-by: Sergey Dyasli <sergey.dyasli@citrix.com>
>> ---
>> RFC --> v1:
>> - Added BUILD_BUG_ON to the netback patch
>> - xenvif_idx_release() now located outside the loop
>>
>> CC: Wei Liu <wei.liu@kernel.org>
>> CC: Paul Durrant <paul@xen.org>
> [snip]
>>
>> +static void __init __maybe_unused build_assertions(void)
>> +{
>> +       BUILD_BUG_ON(sizeof(struct xenvif_tx_cb) > 48);
>
> FIELD_SIZEOF(struct sk_buff, cb) rather than a magic '48' I think.

The macro got renamed recently, so now it should be:

    sizeof_field(struct sk_buff, cb))

Thanks for the suggestion.

--
Sergey

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/dc322a8f-d0ae-dea6-4fe0-cc4d5d14f4d4%40citrix.com.
