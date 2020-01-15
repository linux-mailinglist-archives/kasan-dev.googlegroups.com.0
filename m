Return-Path: <kasan-dev+bncBAABB2XC7PYAKGQEEOHVLJY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53e.google.com (mail-ed1-x53e.google.com [IPv6:2a00:1450:4864:20::53e])
	by mail.lfdr.de (Postfix) with ESMTPS id C748013BE1C
	for <lists+kasan-dev@lfdr.de>; Wed, 15 Jan 2020 12:03:06 +0100 (CET)
Received: by mail-ed1-x53e.google.com with SMTP id v11sf11175269edw.11
        for <lists+kasan-dev@lfdr.de>; Wed, 15 Jan 2020 03:03:06 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1579086186; cv=pass;
        d=google.com; s=arc-20160816;
        b=wPhVSnkFVO03lAuEAG/24da8h4nd9YKIBwQgmbS1a0m4a0x4owyBqroAajXyZ3YIQI
         IP6uSPO4sezMCMt/Uu8NVygDYPMxMtvKbDvSM24HPe/dGDntAVk1aRXB4UZHNPcP9aID
         MEbVun39SPCqQU7h6bNVH9efyQcOvFqj52CGLC9W5AYVkawDtmqAepYxAITwgKyYuu/t
         HjdCb7KwuH3nV+1zzHYlprCKqwIYqZR9Al4kKhdi9INrBIlV4BLw6Elh03Sbr/4/wP5r
         cOMjPkm+j+PoGZyB6nDWkpwMSM25cHlTp44PPS5phX9cC12QL1eUVsIBOEvhE6ro0Zy+
         Cw7g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :mime-version:user-agent:date:message-id:autocrypt:from:references
         :cc:to:subject:ironport-sdr:sender:dkim-signature;
        bh=6RrPXXnAT2cYm6bHGgFswJqskVRJlOP8rxkl4HfSzG0=;
        b=U57Yn6tB+EgkqSFkLClPAxCmJXcD0SjeUGF5gMmAygn/C0RkKLt/U8ehDC+XzWhTvI
         zVfHBIhq/EtogTGgXpE6to7QUSe/2vG5QSiyVz5f06i7PwXsojnWK7S9mNsueLTqkR9b
         iQ+geDpD1wUifUql+e7zrkngML1Yj3GlVPTE6Bij+0oR9nAD6AFJg3YBhKtvwOgaOJnJ
         rq3SLk+Fppd1f9p7Jdy+VnyspgzAOffa4a/axbYlncaNh2OifA3mN+vlgrzjo83MQN0a
         dLdeVdgVi4TQqs83wpNz2w6TgjhVprJy+pYsDe47U078Nnb/TdLq0MLzCGS3ROVdJDxW
         4INw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@citrix.com header.s=securemail header.b=eZsdO68N;
       spf=pass (google.com: domain of sergey.dyasli@citrix.com designates 216.71.155.144 as permitted sender) smtp.mailfrom=sergey.dyasli@citrix.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=citrix.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:ironport-sdr:subject:to:cc:references:from:autocrypt
         :message-id:date:user-agent:mime-version:in-reply-to
         :content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=6RrPXXnAT2cYm6bHGgFswJqskVRJlOP8rxkl4HfSzG0=;
        b=G6VHO21xMy65fEuFfgCnOevc5exjFL+2COCF6KBwhJW7zF1RRJrbj9DC9S4ykWHgFc
         GhpAqN/tSqX7jQmaunMsofnIqbQcJJI9K1top5Q7bzOqQDzzCHYblwRgxQvS8BYETAjj
         IK+5DqI88hKIDVzMdyGtfFq6jx15MpvRMvmudPBt+Yk1cVvGvrM3rQVu+r81KDVlPf6u
         spNm8h7MSegifCltuodHxlipQSaswuq7bc7F5R8sf7LwnMK2ePQq/IgRmEZbjZMJojN9
         4Q3AusFBAq/cJugtXn9U7GSZoYXCZwIYjyS19A7pL09DmDYdjQ6IV1z45BkK752veGS2
         NyXw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:ironport-sdr:subject:to:cc:references
         :from:autocrypt:message-id:date:user-agent:mime-version:in-reply-to
         :content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=6RrPXXnAT2cYm6bHGgFswJqskVRJlOP8rxkl4HfSzG0=;
        b=Me94jpV2hujmf137dqFSM7Jhquc0oRfmSC96iit3vbr/58B0LG1MZDJVKsT6avlW4z
         WlLyqRlRXChD+WGNW07bc7xh/E7qFtn1Ve+8DobG7OU8qB+QOFQ8L9C4wUT9irVzktBv
         BYHdRhZsiyAJPZ2k5/KKaopRtI4puyOsJ1sFyO1jJmfdo7fbn/LrOH0oIwbskEBllUWD
         iVfFCGQrWnQVkU0tRC4IwKeQLnxQ9k9p6WIIxO/43KbjtFIUIXedv73hU6bZOfH158cp
         xH+miU2hst8GRZ3bD4ocTxesbCmB8Yq+BA0MiiMSnSY1SjiwdyVAf4oxC7Y7NB2Godf8
         MHGg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAU87+PAEklszIzh1uP3mC1jlrJDyiPNRhALHhD4KCFn0+HUm3Sq
	oZ3DRpylg7Cq99zvP12Pm70=
X-Google-Smtp-Source: APXvYqysDnj8QqFB/vilidnKshs/d/jsko8UsvRtou9+U/zcpFwWwUfPFms5oA0kkNP1egmwNU90Jg==
X-Received: by 2002:a05:6402:3184:: with SMTP id di4mr28848984edb.59.1579086186396;
        Wed, 15 Jan 2020 03:03:06 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:906:2f0a:: with SMTP id v10ls5237517eji.5.gmail; Wed, 15
 Jan 2020 03:03:05 -0800 (PST)
X-Received: by 2002:a17:906:8595:: with SMTP id v21mr27786385ejx.28.1579086185907;
        Wed, 15 Jan 2020 03:03:05 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1579086185; cv=none;
        d=google.com; s=arc-20160816;
        b=nUNhTgwE8iyo9+8D37zMEoTGSfHvMwzo6f7flu/S0xPkMTerzNr3k57mA3jlJuHGZ4
         2hYPYGU2PcjZOF4pKDsmcD2XfUCC6y8vs+gL+t6Vd9f75kLg0pH1eTcEo5uwRM0URtfl
         NVeovuFjjxd/6P6Z0qd+HEhpbk6PVKgOT/XRQEghyirNylfL/Ldtq+KRhw73LBqI4p5G
         8TIUy4bMq9zpArKkXJdpaYgjE0LginMm7XLC0+oOcDH+NIZKHE6azkTZ+n1AZEVwH2Fx
         fl35hv0X/ziqtJPVWTiU23JhCxfmJ+XVKpMSwVht0/sQzO1oyjwptf/4zb4cqipoRBMS
         ZKMQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:autocrypt:from:references:cc:to:subject
         :ironport-sdr:dkim-signature;
        bh=dwOZ6NozqgN0X9krzN4lo00Io6+pnMrYZ/gU849OIiA=;
        b=tChO36c8naqdQ3h9q7f3NINtdF2fCMh2BdGv57fx8n+wl3/xRpQTBzoxhuv8VRHMhh
         yANcjnIiRvwpcsWzjytbFXAlaooy1dr2OPa3Lamkqnl7PAeSVfk3RimAGy6o3tfNgGIq
         U3dkg4Cra1o7EfRUb8UbI/tRlV8FFuCAPfT1wB3yn+zBrGEhe6J5ejg80cZ0K0S5eEbI
         3BiJapQvXejifJOJzCW55pqTpqwDFW59CWZVZKV1rJX848xWBBnncPgBI3P+uTISagqV
         dMcrRH+aJJo5huybDkH24QoOav7NSRfbzF9XyaFfDM93rDz4s0l4rNtnwu9tWOYPMjsR
         000Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@citrix.com header.s=securemail header.b=eZsdO68N;
       spf=pass (google.com: domain of sergey.dyasli@citrix.com designates 216.71.155.144 as permitted sender) smtp.mailfrom=sergey.dyasli@citrix.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=citrix.com
Received: from esa4.hc3370-68.iphmx.com (esa4.hc3370-68.iphmx.com. [216.71.155.144])
        by gmr-mx.google.com with ESMTPS id w19si810777edr.1.2020.01.15.03.03.05
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 15 Jan 2020 03:03:05 -0800 (PST)
Received-SPF: pass (google.com: domain of sergey.dyasli@citrix.com designates 216.71.155.144 as permitted sender) client-ip=216.71.155.144;
Received-SPF: None (esa4.hc3370-68.iphmx.com: no sender
  authenticity information available from domain of
  sergey.dyasli@citrix.com) identity=pra;
  client-ip=162.221.158.21; receiver=esa4.hc3370-68.iphmx.com;
  envelope-from="sergey.dyasli@citrix.com";
  x-sender="sergey.dyasli@citrix.com";
  x-conformance=sidf_compatible
Received-SPF: Pass (esa4.hc3370-68.iphmx.com: domain of
  sergey.dyasli@citrix.com designates 162.221.158.21 as
  permitted sender) identity=mailfrom;
  client-ip=162.221.158.21; receiver=esa4.hc3370-68.iphmx.com;
  envelope-from="sergey.dyasli@citrix.com";
  x-sender="sergey.dyasli@citrix.com";
  x-conformance=sidf_compatible; x-record-type="v=spf1";
  x-record-text="v=spf1 ip4:209.167.231.154 ip4:178.63.86.133
  ip4:195.66.111.40/30 ip4:85.115.9.32/28 ip4:199.102.83.4
  ip4:192.28.146.160 ip4:192.28.146.107 ip4:216.52.6.88
  ip4:216.52.6.188 ip4:162.221.158.21 ip4:162.221.156.83
  ip4:168.245.78.127 ~all"
Received-SPF: None (esa4.hc3370-68.iphmx.com: no sender
  authenticity information available from domain of
  postmaster@mail.citrix.com) identity=helo;
  client-ip=162.221.158.21; receiver=esa4.hc3370-68.iphmx.com;
  envelope-from="sergey.dyasli@citrix.com";
  x-sender="postmaster@mail.citrix.com";
  x-conformance=sidf_compatible
IronPort-SDR: +bTwz3rb6Pt3yrpWyywqXjEWMAEX4c/82keB2YSJFPUWl/kcbbp2jzBF6YJLhblAe5aQQSPmR7
 rI7wZtHwQde4uW5qpPSinMb78Ic3EMYVWzAGZnfYTgDu3LiA35p7bGZtADGLRBNrvysnn5FLDj
 qlpRsdr71du8mWbVbsQNBNWiWyWfmWeVK3ke5dyiGb2H/RqHwkPUnYG8gYIJBEwLByUfsCCTqz
 IAV/sJbl6naA1Yddf4fs77C6vBgXR5tCfUWRdJ5i7m0JtnDKiPNqSaEicfs7YcOGgDUfeNGEr2
 J10=
X-SBRS: 2.7
X-MesageID: 11527758
X-Ironport-Server: esa4.hc3370-68.iphmx.com
X-Remote-IP: 162.221.158.21
X-Policy: $RELAYED
X-IronPort-AV: E=Sophos;i="5.70,322,1574139600"; 
   d="scan'208";a="11527758"
Subject: Re: [PATCH v1 4/4] xen/netback: Fix grant copy across page boundary
 with KASAN
To: Vlastimil Babka <vbabka@suse.cz>, <xen-devel@lists.xen.org>,
	<kasan-dev@googlegroups.com>, <linux-mm@kvack.org>,
	<linux-kernel@vger.kernel.org>
CC: Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko
	<glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, Boris Ostrovsky
	<boris.ostrovsky@oracle.com>, Juergen Gross <jgross@suse.com>, "Stefano
 Stabellini" <sstabellini@kernel.org>, George Dunlap
	<george.dunlap@citrix.com>, Ross Lagerwall <ross.lagerwall@citrix.com>,
	Andrew Morton <akpm@linux-foundation.org>, Wei Liu <wei.liu@kernel.org>,
	"Paul Durrant" <paul@xen.org>, "sergey.dyasli@citrix.com >> Sergey Dyasli"
	<sergey.dyasli@citrix.com>
References: <20200108152100.7630-1-sergey.dyasli@citrix.com>
 <20200108152100.7630-5-sergey.dyasli@citrix.com>
 <26c43c43-b303-938c-2f26-8e0144159e29@suse.cz>
From: Sergey Dyasli <sergey.dyasli@citrix.com>
Autocrypt: addr=sergey.dyasli@citrix.com; keydata=
 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
Message-ID: <e0663153-35e0-32ef-87a5-39189c440a3d@citrix.com>
Date: Wed, 15 Jan 2020 11:02:59 +0000
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101
 Thunderbird/68.2.2
MIME-Version: 1.0
In-Reply-To: <26c43c43-b303-938c-2f26-8e0144159e29@suse.cz>
Content-Type: text/plain; charset="UTF-8"
Content-Language: en-US
X-Original-Sender: sergey.dyasli@citrix.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@citrix.com header.s=securemail header.b=eZsdO68N;       spf=pass
 (google.com: domain of sergey.dyasli@citrix.com designates 216.71.155.144 as
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

On 09/01/2020 10:33, Vlastimil Babka wrote:
> On 1/8/20 4:21 PM, Sergey Dyasli wrote:
>> From: Ross Lagerwall <ross.lagerwall@citrix.com>
>>
>> When KASAN (or SLUB_DEBUG) is turned on, the normal expectation that
>> allocations are aligned to the next power of 2 of the size does not
>> hold.
>
> Hmm, really? They should after 59bb47985c1d ("mm, sl[aou]b: guarantee
> natural alignment for kmalloc(power-of-two)"), i.e. since 5.4.
>
> But actually the guarantee is only for precise power of two sizes given
> to kmalloc(). Allocations of sizes that end up using the 96 or 192 bytes
> kmalloc cache have no such guarantee. But those might then cross page
> boundary also without SLUB_DEBUG.

That's interesting to know. It's certainly not the case for 4.19 kernel
for which PV KASAN was initially developed. But I guess this means that
only patch description needs updating.

>
>> Therefore, handle grant copies that cross page boundaries.
>>
>> Signed-off-by: Ross Lagerwall <ross.lagerwall@citrix.com>
>> Signed-off-by: Sergey Dyasli <sergey.dyasli@citrix.com>

--
Thanks,
Sergey

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/e0663153-35e0-32ef-87a5-39189c440a3d%40citrix.com.
