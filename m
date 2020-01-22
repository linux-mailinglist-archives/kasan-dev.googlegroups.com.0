Return-Path: <kasan-dev+bncBAABB3V5UDYQKGQEGOKVEVY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x139.google.com (mail-il1-x139.google.com [IPv6:2607:f8b0:4864:20::139])
	by mail.lfdr.de (Postfix) with ESMTPS id A1B9514521F
	for <lists+kasan-dev@lfdr.de>; Wed, 22 Jan 2020 11:07:43 +0100 (CET)
Received: by mail-il1-x139.google.com with SMTP id c5sf4434257ilo.9
        for <lists+kasan-dev@lfdr.de>; Wed, 22 Jan 2020 02:07:43 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1579687662; cv=pass;
        d=google.com; s=arc-20160816;
        b=hyV69XDRRhzmnhhmeN5e+UN669Y2BJTjTYfb4dd/NwA6sUEkxdpODQedHfmjIy32tF
         SdW1uaYTiBZvPaEqbzrYm705rZlDdDgwe4+LKrVGjfmebjYR7KTsPjv710CeZsMK3ZhF
         3imiF6Kv13/JH5O1pdJfqNhnT8UzIFgpFKAltMnc8FoRG1IN0LwZys3pMbdYsDXPRxmJ
         sw4SBX3JURb7BgWbhiC4FwZTM9VngEhfmEo3WrcB5NHRRuJqTuUIez6xCo/b0b2A866N
         IFIID44kSExunGcxsutxXU+0wnkb/N/VL6B3/MRGWL+/t6dW31FTtfEk4WZKQHhb4bV7
         FPGg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :mime-version:user-agent:date:message-id:autocrypt:from:references
         :cc:to:subject:ironport-sdr:sender:dkim-signature;
        bh=hvcoChAW/k8RCeDEZYVnOsiGbIj0KFr6ZtMLS7Pr/+g=;
        b=dj2fb4D6yHG1oHHgALhX1oIGiu0DFddnxknef9TMjw1wj+U0bpcJGCIjAxXsQoTHNi
         FRUOg5JBcIj2osEZeLB5rm4CA2sl1chakSGKLD3gEwLe1CFjdIpqUgh7DuLiXSaob2OB
         Ko9gw3lfr7TMHf3QasPC1rDUP77ZfofSYsK82Pg1+tKteJKkn/M47Qlrdv2TdBEMlnXZ
         2udaLkHCy5JxuHJaJyhBibKqplLQwXWZ1OPw0lzh+C5VkdmvRUqn4jBoDFdWOOFSL8Ny
         qzib7ilNvRtTpkJl6NPdo4eAUaEQjFsEkBNYZAoaUrwPcfZX2feXTUrf1O4XMcfG418j
         1P8Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@citrix.com header.s=securemail header.b=HEJmoLVE;
       spf=pass (google.com: domain of sergey.dyasli@citrix.com designates 216.71.145.153 as permitted sender) smtp.mailfrom=sergey.dyasli@citrix.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=citrix.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:ironport-sdr:subject:to:cc:references:from:autocrypt
         :message-id:date:user-agent:mime-version:in-reply-to
         :content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=hvcoChAW/k8RCeDEZYVnOsiGbIj0KFr6ZtMLS7Pr/+g=;
        b=D+PSghcPQd3Nque2XIVyq0d7pUG3mhZ7HnQoll8R0dGuwM40cvIJkd28Ap9tOqy4zr
         dgFOpGMzcP7NTTFuafLkyw62jZ4YQEXFKg+V+2VWZQiFPbElbE/ugAUIhgT1l8FrUR9C
         9iDr0YtSWetp8Br6vDgUb0aTAl7GL9G/40EMgzkFzZ18VdDgaatg50BgHC/dAx7O1gey
         u9FQNOK4ay3ogPx8fVVKHVzPIgmqJUkLteJii4+b9okXWZGeadyJxDEzDC/ZFrolbtnR
         IJDLazTjsS0Y4IpJL31/57e8BTPMaB6EDHNMujxG7QcLnI/eLeLXaNzbRpIKIfWU3KFb
         1guA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:ironport-sdr:subject:to:cc:references
         :from:autocrypt:message-id:date:user-agent:mime-version:in-reply-to
         :content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=hvcoChAW/k8RCeDEZYVnOsiGbIj0KFr6ZtMLS7Pr/+g=;
        b=PJUzpzabgU7GS/V3KZ8A9A7e+tjYr1JOXPIrtxxXEIq2ffC6Z5DbWeyZTROU7SEejj
         5LoHeTmSaDik3wf3ECu788i1FImJ30jx145K9PEu2BGhDHFPB8lYuZm/5mbJ5v4A00/A
         qRMl21m/Hp25etEcFfXn1E9+pSs5ZinOYZbq6529ebWkcGxGAxXPtpnsRUzLrlx+JlDI
         LhVTEanpQ5hSZD1pvlComprvNOsqE0FLe9XoB9rYijw8chYIIEicxdgZw89xgyedkPbY
         ykwEzW2zFfmeMeQMINbzx7ZKfiDeZEROjQajd2i0UuqRoq60jX9Cvlj1aKeeWtWNBh9S
         FEhw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAWxrOpi/SeJx3ZzDYEnOd/Jn3ZEeNi690hNvTLTc58fX9sU+WRf
	fcOXieVq2UrU4WMmkAnCIks=
X-Google-Smtp-Source: APXvYqxxZWYwijYlH0cMW7SwHwqarT1GB2GkXBeCgoiOJ2jdHxkdNNXzR+QtHp6Uigc0AcUGelIl2w==
X-Received: by 2002:a92:bf10:: with SMTP id z16mr7460347ilh.87.1579687662396;
        Wed, 22 Jan 2020 02:07:42 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a92:5d90:: with SMTP id e16ls6762943ilg.4.gmail; Wed, 22 Jan
 2020 02:07:42 -0800 (PST)
X-Received: by 2002:a92:d3cd:: with SMTP id c13mr6862963ilh.21.1579687661999;
        Wed, 22 Jan 2020 02:07:41 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1579687661; cv=none;
        d=google.com; s=arc-20160816;
        b=eMe/cEbCzipoAmcli6KUds8H+aznyIvU6WFOo1XFqvX2bELPA9bYlzEUGMl2nr+Gkw
         W8ZUXnvW3D7SLm5fynkvOTttZxGSOCLZxnD4w9awfDepo5PQHt/1l/qoQuZxnLca7pgR
         F2HrNjQSl+XmoNgs1xpM+gax+RU1RR/YzYD2HbsqQbHVzXsLYWDEXDF+4PimjxdjIGa4
         54LSr7b4cxC3ufyFaUC9np3tqutHGzYJj0kEpwwOoYVpL1SeM4HtX/KGmLPS0fhkmsF5
         ado23K827mWyJZn6Fgj5SMiUAT/EDwnswFm9Nso464ogq35gu6L1cwRqW1Oj+LNW31zk
         64cg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:autocrypt:from:references:cc:to:subject
         :ironport-sdr:dkim-signature;
        bh=g8zwr+5Z1U64v1L7b14YYEycHrewuTXF5B3e5sG8dsE=;
        b=HswLg3/NSrLeBK8u2hAjwlNOrCj/tDLO0gOUfO1EgG6bicYL8XO1/4s5y2SGv3bi7p
         2T3XIp9+AOS5g8R5kcfirsC2F7cprzjdbIDYAVK9wnwPfXQ9eJLwZFtQI1CFIJ6dXEoD
         KtQ2fFNhrShrrxcv6uG8ebuBOFSRy4OniO4hMBGW64Mb/HZq2jWgr2cf5H5iGgak6STB
         YNckPbAwZMOz/atoHg+uL5ObMCyGxMMsxR82asGmAe3dVA3ljyfT9bPsK3hA4xNoa9EG
         ITSFc3IquvHnXv8z/ZNaMkV0dsUkQTMvC7wwcfSflgnL2qpcwV71AnoGVMoQ3dX3NM3l
         8SPg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@citrix.com header.s=securemail header.b=HEJmoLVE;
       spf=pass (google.com: domain of sergey.dyasli@citrix.com designates 216.71.145.153 as permitted sender) smtp.mailfrom=sergey.dyasli@citrix.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=citrix.com
Received: from esa2.hc3370-68.iphmx.com (esa2.hc3370-68.iphmx.com. [216.71.145.153])
        by gmr-mx.google.com with ESMTPS id f85si1824350ilg.2.2020.01.22.02.07.41
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 22 Jan 2020 02:07:41 -0800 (PST)
Received-SPF: pass (google.com: domain of sergey.dyasli@citrix.com designates 216.71.145.153 as permitted sender) client-ip=216.71.145.153;
Received-SPF: None (esa2.hc3370-68.iphmx.com: no sender
  authenticity information available from domain of
  sergey.dyasli@citrix.com) identity=pra;
  client-ip=162.221.158.21; receiver=esa2.hc3370-68.iphmx.com;
  envelope-from="sergey.dyasli@citrix.com";
  x-sender="sergey.dyasli@citrix.com";
  x-conformance=sidf_compatible
Received-SPF: Pass (esa2.hc3370-68.iphmx.com: domain of
  sergey.dyasli@citrix.com designates 162.221.158.21 as
  permitted sender) identity=mailfrom;
  client-ip=162.221.158.21; receiver=esa2.hc3370-68.iphmx.com;
  envelope-from="sergey.dyasli@citrix.com";
  x-sender="sergey.dyasli@citrix.com";
  x-conformance=sidf_compatible; x-record-type="v=spf1";
  x-record-text="v=spf1 ip4:209.167.231.154 ip4:178.63.86.133
  ip4:195.66.111.40/30 ip4:85.115.9.32/28 ip4:199.102.83.4
  ip4:192.28.146.160 ip4:192.28.146.107 ip4:216.52.6.88
  ip4:216.52.6.188 ip4:162.221.158.21 ip4:162.221.156.83
  ip4:168.245.78.127 ~all"
Received-SPF: None (esa2.hc3370-68.iphmx.com: no sender
  authenticity information available from domain of
  postmaster@mail.citrix.com) identity=helo;
  client-ip=162.221.158.21; receiver=esa2.hc3370-68.iphmx.com;
  envelope-from="sergey.dyasli@citrix.com";
  x-sender="postmaster@mail.citrix.com";
  x-conformance=sidf_compatible
IronPort-SDR: vMRjz/muvrzwffZ9gPdAkzOUaYy9fd6F78rjNgWjA+E4IrmOT4iUvZoLuMWmHiiID1Own4xeCv
 TTEFoxCLO0ynfKfwXsKjsen+Q6U5ExT5FZj3v02meT9wHVyfNOIz7Q5wFMv/c9/i8H5OaNDmvh
 nlai6MElcKtJaJBzKeVUrv4MtVGjtptShv3QnmR/wz4kQ7WeRURg83hdt8nY+TiAp6YU0W8zjv
 GaNx5omxl14S8EncuOU9JVydX0d78Q3ZKy+JOzG90YjDhFWXZurtNmqEGkNbT7kfgdQmV7EuBz
 H1o=
X-SBRS: 2.7
X-MesageID: 11271803
X-Ironport-Server: esa2.hc3370-68.iphmx.com
X-Remote-IP: 162.221.158.21
X-Policy: $RELAYED
X-IronPort-AV: E=Sophos;i="5.70,349,1574139600"; 
   d="scan'208";a="11271803"
Subject: Re: [PATCH v2 4/4] xen/netback: fix grant copy across page boundary
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
References: <20200117125834.14552-1-sergey.dyasli@citrix.com>
 <20200117125834.14552-5-sergey.dyasli@citrix.com>
 <CACCGGhApXXnQwfBN_LioAh+8bk-cAAQ2ciua-MnnQoMBUfap6g@mail.gmail.com>
From: Sergey Dyasli <sergey.dyasli@citrix.com>
Autocrypt: addr=sergey.dyasli@citrix.com; keydata=
 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
Message-ID: <85b36733-7f54-fdfd-045d-b8e8a92d84c5@citrix.com>
Date: Wed, 22 Jan 2020 10:07:35 +0000
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101
 Thunderbird/68.2.2
MIME-Version: 1.0
In-Reply-To: <CACCGGhApXXnQwfBN_LioAh+8bk-cAAQ2ciua-MnnQoMBUfap6g@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"
Content-Language: en-US
X-Original-Sender: sergey.dyasli@citrix.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@citrix.com header.s=securemail header.b=HEJmoLVE;       spf=pass
 (google.com: domain of sergey.dyasli@citrix.com designates 216.71.145.153 as
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

On 20/01/2020 08:58, Paul Durrant wrote:
> On Fri, 17 Jan 2020 at 12:59, Sergey Dyasli <sergey.dyasli@citrix.com> wrote:
>>
>> From: Ross Lagerwall <ross.lagerwall@citrix.com>
>>
>> When KASAN (or SLUB_DEBUG) is turned on, there is a higher chance that
>> non-power-of-two allocations are not aligned to the next power of 2 of
>> the size. Therefore, handle grant copies that cross page boundaries.
>>
>> Signed-off-by: Ross Lagerwall <ross.lagerwall@citrix.com>
>> Signed-off-by: Sergey Dyasli <sergey.dyasli@citrix.com>
>> ---
>> v1 --> v2:
>> - Use sizeof_field(struct sk_buff, cb)) instead of magic number 48
>> - Slightly update commit message
>>
>> RFC --> v1:
>> - Added BUILD_BUG_ON to the netback patch
>> - xenvif_idx_release() now located outside the loop
>>
>> CC: Wei Liu <wei.liu@kernel.org>
>> CC: Paul Durrant <paul@xen.org>
>
> Acked-by: Paul Durrant <paul@xen.org>

Thanks! I believe this patch can go in independently from the other
patches in the series. What else is required for this?

--
Sergey

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/85b36733-7f54-fdfd-045d-b8e8a92d84c5%40citrix.com.
