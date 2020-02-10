Return-Path: <kasan-dev+bncBAABB2FUQXZAKGQENZXEHVI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x539.google.com (mail-ed1-x539.google.com [IPv6:2a00:1450:4864:20::539])
	by mail.lfdr.de (Postfix) with ESMTPS id A1FCA157B22
	for <lists+kasan-dev@lfdr.de>; Mon, 10 Feb 2020 14:28:08 +0100 (CET)
Received: by mail-ed1-x539.google.com with SMTP id ay24sf6124117edb.0
        for <lists+kasan-dev@lfdr.de>; Mon, 10 Feb 2020 05:28:08 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1581341288; cv=pass;
        d=google.com; s=arc-20160816;
        b=W/uPAneeJ07Uew+GXN0ig17uhD/pV+QFh2nm/xhfAsgfsfpt3YNe504ja6ctGxxyhT
         9exb10ZxiE5CTafBQ6O/0LcSs77iXza46rm+1+zBrEInu6Ikt0UH61J+K5rubfXsmWUk
         yG6hSMd20X2VoIdCitOC4IA5Hlu/yjDD21TvO66jZ0K96f8ms09lePsYy7NWjmAaGRgL
         7msuEdy6Cl3a1RXboRTQFQ/jKTK2SnK/ZkvVtUWK5LJJBWUQjQfQZwKUSIXmXDOEDxY9
         b68G0YQLUAd4MlgJ41p7YaHCJ07/rz9uDq49zTsqqPyZY/wcdJBIdT2qKnGta5DPp67I
         mP3Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :mime-version:user-agent:date:message-id:autocrypt:from:references
         :cc:to:subject:ironport-sdr:sender:dkim-signature;
        bh=ZYMNnJuS2efoxLklWFjnimPYhoHuXUX8GNziCRlWUr0=;
        b=tUV2pghDhmHizkyKcxKwiNTfGp8B015FdHnXor0j5hyNSG+lEk44m9I2W13VdVxdFq
         gTeUVEyPHm/Yurl7WR7KolEcEE4npKAy7MKGDSFstSURwq/LXLylsAqcpg4nknWUFCU4
         42Yepv7gJSnvVzhNYDH/ipFRMcyUuCgpxb2Hk6OxXz3yiMUE+uQxLtHsPNnKFXnLClST
         uGZe3z/Zva9YFuALWfPM51Tn0JN4wWgSJoOM2ljZ/UEy2JLvPFgXdM0cT2yHpH+Zd1jm
         mjgqZr3V/j9fCcLVyOBeSdphsbS0ECz9AvTpwo8izjnqKbylCwp/DMdT2m0rZt7F6Ker
         M6hg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@citrix.com header.s=securemail header.b=RGgk3lkR;
       spf=pass (google.com: domain of sergey.dyasli@citrix.com designates 216.71.155.168 as permitted sender) smtp.mailfrom=sergey.dyasli@citrix.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=citrix.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:ironport-sdr:subject:to:cc:references:from:autocrypt
         :message-id:date:user-agent:mime-version:in-reply-to
         :content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=ZYMNnJuS2efoxLklWFjnimPYhoHuXUX8GNziCRlWUr0=;
        b=h3yJVxm6P9DMlfI8iiMALGNT2ZzexSzn3Jz05SIqWtjebpvBKY1PC78irENJTlky4p
         BaMlp8c/eNvVJE77zcTeX9kkR6XK3b/ttPq4NfkdkBOeBtfUEmyILSrRH/42Xsc61p26
         1FWR/V4ULRmqIoLv+NfNQcbIA1zYoQat5UjNYgctYW/ExbDG1tXVaiN0H6zocrqF3/fr
         f81uIQurhQnPB3HIDnuijm5AuHjhL2dbr087A7xKsT3fzTrNwWsjKkMB3hzBnfnyOv4X
         JCRN3bBNleyiITD4mq1F14z5CsedIdFjQlgZLII0Xn6eCYIGB+uL0YpvwUxpANofyWET
         70eA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:ironport-sdr:subject:to:cc:references
         :from:autocrypt:message-id:date:user-agent:mime-version:in-reply-to
         :content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ZYMNnJuS2efoxLklWFjnimPYhoHuXUX8GNziCRlWUr0=;
        b=d/S3Bt7zEv5RzZ6+z4zs4rXVhFBmtSdFlYv6JRS+iOvQYzP7+ZR15M5HYxpT4rqo/e
         xDjkbIYVRtrVSAILD8sRbfwgzqLL4Ph16LewEZlXMZwzyeJW0Ad7fm7XS4woOV5ZIqHl
         tnM6PQMacUO58HY/smdrTFLbLiNctFZ2wbDWIyxyQF7b0i/IW6dTpPyR138FjFYaD6zm
         62Hj5gu6TCH9arVJ2j+JpoWD4CbLM7jnnYTmDcDA8+hUKDSQW0lub5K2TMQ/ma69X8mu
         9szyFanhzsD8XO1H/DvEqfXFIbgg23BU3kINY+UfA5M355hl+N9G/Cs8vG9wJR877jx4
         oLYQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAVg6Adp/q7xa08G/5mZn/vJo8TDiOZ0LSURY22IjFY96CaVuX2O
	xvlo0LlAgUMOYbyPtyKG2l4=
X-Google-Smtp-Source: APXvYqwl1qBVoZcyTxIw64tgiRyH9A/7h+9If3BnL0amZCyXf8/+6jM1JUYgbOVDEUZzvj6dmqttxA==
X-Received: by 2002:a17:906:9458:: with SMTP id z24mr1128493ejx.155.1581341288391;
        Mon, 10 Feb 2020 05:28:08 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:907:118d:: with SMTP id uz13ls4330641ejb.0.gmail; Mon,
 10 Feb 2020 05:28:08 -0800 (PST)
X-Received: by 2002:a17:906:31cb:: with SMTP id f11mr1107728ejf.337.1581341287928;
        Mon, 10 Feb 2020 05:28:07 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1581341287; cv=none;
        d=google.com; s=arc-20160816;
        b=ljR5MbPWEnI/iIbbwZnVqIPsZaJ9cvO7MtgA4eUVNKOSFd2njV46sv1Ev8VrdXImF6
         Sq1lFv16Q8kGJENNpNFADTvhESiyoJOdcWS1KRKul4ianpfTiW/4/U5XOYiiPdDqZpKt
         Tfc00COhpUJHfCKMiW8er2CcCoxKG46tj7wbG4MHXqZ04FlC5WjClid04mLb0ER6XNUA
         FRSaO3hIqhn/BYnDuO2hAC5P7gNq2Plq5TUvnPBI1H9DJUZ7n0HoFDySeptcni0QvUqm
         SggucKdNGscI6J3zS+e0rGBaBpYhTL8CPxW1JSHKIGndz9wY/Ik/Gh1QFikJwxUTaUbL
         lB2Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:autocrypt:from:references:cc:to:subject
         :ironport-sdr:dkim-signature;
        bh=SpEMOfPBLrN92qlVDm54s2jDhs4qZaUUjlcX2OY0qvg=;
        b=Ms95avlUWtg5jUAa+PewdosP8sNCDrWAQ5+dnQTHcXGoYAvaoOCK6YuNzN3liQz36N
         k0rUS6DxRZtDgcJKdO3ju1zoHZ0f01zrDuMLE7Se9bcDBFikXI31xvJpuM9EvCy9U/sk
         ZiRg5iwhpjkPXhcW0l366RIvPfoFYLw8XXxIpFyBCATankxeapnlLsxklXOlYPQEdcki
         KFKMbeHtvO8vPNhK0hcCFrO3kzPcTtrdGHNLlGcc6QGE+KaF3sPENazSXpN9AO3SPKL5
         jnm/j1J+lWGWne3lKLWt6SrzjwIfyihsQZJVviexljNJi7ErVBx6iqIFHnZ7eq622XHN
         Mqpw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@citrix.com header.s=securemail header.b=RGgk3lkR;
       spf=pass (google.com: domain of sergey.dyasli@citrix.com designates 216.71.155.168 as permitted sender) smtp.mailfrom=sergey.dyasli@citrix.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=citrix.com
Received: from esa5.hc3370-68.iphmx.com (esa5.hc3370-68.iphmx.com. [216.71.155.168])
        by gmr-mx.google.com with ESMTPS id n1si28582edw.4.2020.02.10.05.28.07
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 10 Feb 2020 05:28:07 -0800 (PST)
Received-SPF: pass (google.com: domain of sergey.dyasli@citrix.com designates 216.71.155.168 as permitted sender) client-ip=216.71.155.168;
Received-SPF: None (esa5.hc3370-68.iphmx.com: no sender
  authenticity information available from domain of
  sergey.dyasli@citrix.com) identity=pra;
  client-ip=162.221.158.21; receiver=esa5.hc3370-68.iphmx.com;
  envelope-from="sergey.dyasli@citrix.com";
  x-sender="sergey.dyasli@citrix.com";
  x-conformance=sidf_compatible
Received-SPF: Pass (esa5.hc3370-68.iphmx.com: domain of
  sergey.dyasli@citrix.com designates 162.221.158.21 as
  permitted sender) identity=mailfrom;
  client-ip=162.221.158.21; receiver=esa5.hc3370-68.iphmx.com;
  envelope-from="sergey.dyasli@citrix.com";
  x-sender="sergey.dyasli@citrix.com";
  x-conformance=sidf_compatible; x-record-type="v=spf1";
  x-record-text="v=spf1 ip4:209.167.231.154 ip4:178.63.86.133
  ip4:195.66.111.40/30 ip4:85.115.9.32/28 ip4:199.102.83.4
  ip4:192.28.146.160 ip4:192.28.146.107 ip4:216.52.6.88
  ip4:216.52.6.188 ip4:162.221.158.21 ip4:162.221.156.83
  ip4:168.245.78.127 ~all"
Received-SPF: None (esa5.hc3370-68.iphmx.com: no sender
  authenticity information available from domain of
  postmaster@mail.citrix.com) identity=helo;
  client-ip=162.221.158.21; receiver=esa5.hc3370-68.iphmx.com;
  envelope-from="sergey.dyasli@citrix.com";
  x-sender="postmaster@mail.citrix.com";
  x-conformance=sidf_compatible
IronPort-SDR: v27w17BgUeGjtp/rl+JvfJKbl+EaZoEoDjOXy+AxgNKoUVuR3HsBp3/YwqB9C4hhsfHfEiE5R8
 Whp2yvSJsJIZGHYa4NCcKw23XExw6bKzW3EMqZcR6rU8AvrEaseHho+J2sSxsiS3elFH0s0Ja0
 soe8U2ZuKnE5dtm/45/ysKOJjCySAWU8mJCVOf8aabf41Wa/kPUnRQlQDPiBOOUdHjg0MfKRgb
 h5R+0CQLPMCQ0uAK1uf+ztaHPEZ1AYc+pLaw6b6CVKL34Mz9s6NHWfx0Vt1uvPZ6aSMvam2HSV
 csE=
X-SBRS: 2.7
X-MesageID: 12569220
X-Ironport-Server: esa5.hc3370-68.iphmx.com
X-Remote-IP: 162.221.158.21
X-Policy: $RELAYED
X-IronPort-AV: E=Sophos;i="5.70,425,1574139600"; 
   d="scan'208";a="12569220"
Subject: Re: [PATCH v3 4/4] xen/netback: fix grant copy across page boundary
To: David Miller <davem@davemloft.net>
CC: <xen-devel@lists.xen.org>, <kasan-dev@googlegroups.com>,
	<linux-mm@kvack.org>, <linux-kernel@vger.kernel.org>,
	<aryabinin@virtuozzo.com>, <glider@google.com>, <dvyukov@google.com>,
	<boris.ostrovsky@oracle.com>, <jgross@suse.com>, <sstabellini@kernel.org>,
	<george.dunlap@citrix.com>, <ross.lagerwall@citrix.com>,
	<akpm@linux-foundation.org>, <netdev@vger.kernel.org>, <wei.liu@kernel.org>,
	<paul@xen.org>, "sergey.dyasli@citrix.com >> Sergey Dyasli"
	<sergey.dyasli@citrix.com>
References: <20200207142652.670-1-sergey.dyasli@citrix.com>
 <20200207142652.670-5-sergey.dyasli@citrix.com>
 <20200207.153630.1432371073271757175.davem@davemloft.net>
From: Sergey Dyasli <sergey.dyasli@citrix.com>
Autocrypt: addr=sergey.dyasli@citrix.com; keydata=
 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
Message-ID: <db55bbec-e685-e3b6-638a-3d707d8892c0@citrix.com>
Date: Mon, 10 Feb 2020 13:27:38 +0000
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101
 Thunderbird/68.4.1
MIME-Version: 1.0
In-Reply-To: <20200207.153630.1432371073271757175.davem@davemloft.net>
Content-Type: text/plain; charset="UTF-8"
Content-Language: en-US
X-Original-Sender: sergey.dyasli@citrix.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@citrix.com header.s=securemail header.b=RGgk3lkR;       spf=pass
 (google.com: domain of sergey.dyasli@citrix.com designates 216.71.155.168 as
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

On 07/02/2020 14:36, David Miller wrote:
> From: Sergey Dyasli <sergey.dyasli@citrix.com>
> Date: Fri, 7 Feb 2020 14:26:52 +0000
>
>> From: Ross Lagerwall <ross.lagerwall@citrix.com>
>>
>> When KASAN (or SLUB_DEBUG) is turned on, there is a higher chance that
>> non-power-of-two allocations are not aligned to the next power of 2 of
>> the size. Therefore, handle grant copies that cross page boundaries.
>>
>> Signed-off-by: Ross Lagerwall <ross.lagerwall@citrix.com>
>> Signed-off-by: Sergey Dyasli <sergey.dyasli@citrix.com>
>> Acked-by: Paul Durrant <paul@xen.org>
>
> This is part of a larger patch series to which netdev was not CC:'d
>
> Where is this patch targetted to be applied?
>
> Do you expect a networking ACK on this?
>
> Please do not submit patches in such an ambiguous manner like this
> in the future, thank you.

Please see the following for more context:

    https://lore.kernel.org/linux-mm/20200122140512.zxtld5sanohpmgt2@debian/

Sorry for not providing enough context with this submission.

--
Thanks,
Sergey

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/db55bbec-e685-e3b6-638a-3d707d8892c0%40citrix.com.
