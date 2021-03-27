Return-Path: <kasan-dev+bncBCUJ7YGL3QFBBVUV7SBAMGQEUZACOBA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x340.google.com (mail-ot1-x340.google.com [IPv6:2607:f8b0:4864:20::340])
	by mail.lfdr.de (Postfix) with ESMTPS id CA33934B642
	for <lists+kasan-dev@lfdr.de>; Sat, 27 Mar 2021 11:37:11 +0100 (CET)
Received: by mail-ot1-x340.google.com with SMTP id x68sf6137658ota.2
        for <lists+kasan-dev@lfdr.de>; Sat, 27 Mar 2021 03:37:11 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1616841430; cv=pass;
        d=google.com; s=arc-20160816;
        b=Ko1ZlYNSzaBOyv5xxGq3lfnfUCiWARYypPutSF1Hj9+QWtQHmjFmchTJri7H1GZtbb
         75KP2vnSp2G2zzpQnsKQ9Y5MhFPW/B3puqNmp1JQ1dvzwu70SkSaVde0JELD1t1h0Af9
         TZS5im9qCscGij6a1z4doTwQI4iCMhlmsBfCk5br2IA4WTQDVT+1pLa1liH0U0P/lsAt
         P4cCokL+y+UalpBmEaaFleAcNq1ZiMKJiFF9reO1dxg/zgQTg/vJhJArzCIzKKDTA/C9
         9yeORhUeOXeTKx5YoIv/x/T+SvLzla8uOyPWszJzuyfyTrzn/OchtbpMgkdMSzYkcZML
         g1GA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=9LmkGQZWpDrjdB4nRjY5OLJcGbnprkFDCt+xvIt6YtQ=;
        b=QuUpvKnGQ85wAJQP5IdZN5Ji1aDxq+Nr9PU8eRyp+nRPc6Th1L/s62V00fRyIddsSW
         wVu8yRiiHrd5TQ9t3vGCKpb8WhwVJwJ6rI1t2zJC65541boFcN1wuYemQIJDA3txRfBE
         3F6Lml2+UFEueveA2WAt8P2YO5c3I4xnh17gV2UsuEiUUX68cC3yq57llfymVW4Zw7ft
         IKjKej/L3n7ZWazQVW2uxKavPYlLjsfyI4XBxQNq7J+Zzugo38JQ0+TW2YWHOB/v9Q9+
         z+t2nl++CDDWq7fGgD2Wai/Zc8StHe7vgsOHcISjovTaCt4GtS2DwUr9IRIB6YMdbYpP
         8HRQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linuxfoundation.org header.s=korg header.b=DSyPj5Ws;
       spf=pass (google.com: domain of gregkh@linuxfoundation.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=gregkh@linuxfoundation.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linuxfoundation.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=9LmkGQZWpDrjdB4nRjY5OLJcGbnprkFDCt+xvIt6YtQ=;
        b=KzHg+xOuwN2RtWu1I2iwPxybLgT4BJSgsD24t1a53LqfYyxl+Buglx35ncKk2et4cG
         EaKnB6VsartFY7watnNy0bSTrYDVACaDN5ELMZjOQx4peO0EsUSuRlHiAf9uq6/L4lAk
         z3Fr+g7Bgynk6hpnR1yGIqUjoEb0OVDrQalxokhn+YnwRz03gmDNRLDyXYfw9cIR85I0
         QtLazCQxdUG0xWr+7y06X1Wfp2grE0yICw1sUmLflOfGqUavJxXXn3xKPGpu7iZA3VQd
         OZD2+cV1fmZWQ3BXp2yHED9siNmQbVXjplBEH8HjzVs6guSJOHGFBB2An5DTwwV94A0r
         BRRw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=9LmkGQZWpDrjdB4nRjY5OLJcGbnprkFDCt+xvIt6YtQ=;
        b=QbqDgiZKnDxE2zk4xLqkw8/xPL0eJv5k+L+OinQe19+HPlTuCy0A9HGd7LyhRj8giP
         iUZqhcyo5NRBdXpo4iTQtwFxMZJnMS4I1wkDriHhUhyY7AjCEwtxAo4GWJ1k394niwQd
         0By10dB+xvaRdhz8wI8xdzH6FnYTHE96lVl24M7f61jS2rp8laMNEDbhdszia1SQtj5A
         3GLkf65SVYE5y1+EdyfukOeHu1F+Q1V98mYluH4J0vRNOVwg8Xo2fHt8n2qo0J+GtWYz
         zc2FQi/4Dk0Oo0eOVStq4dIyj4ok02YbS38rJdAbO0eIEuSFQJw+C0T6lQKKcoXs9p0f
         P9Xg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530NoBFkFb8MBLZzXp5KLIWxxPliQT+NcX8vvk05Zpk4Id2VPkJe
	ACqSLLIU/KfIZAEIynAJt74=
X-Google-Smtp-Source: ABdhPJxz+CfGYqhhAZSkVtWrbrrYf1HNMn9LsgajPpMp8PwN45F1j0jxwDf9xuZYDSnRJspVyv+f0g==
X-Received: by 2002:a9d:8d5:: with SMTP id 79mr15551670otf.345.1616841430792;
        Sat, 27 Mar 2021 03:37:10 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aca:5c5:: with SMTP id 188ls2808546oif.6.gmail; Sat, 27 Mar
 2021 03:37:10 -0700 (PDT)
X-Received: by 2002:aca:3d86:: with SMTP id k128mr12991426oia.86.1616841430508;
        Sat, 27 Mar 2021 03:37:10 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1616841430; cv=none;
        d=google.com; s=arc-20160816;
        b=poiOzzvvKBCgriE+QJO2onkzU3tSLdW1y/klnvofcRLUo4FTR30LMOwbUEg0vRUCG8
         SSdl8MJ1Amk8M3jAiCiK6+tTDE48ukK0XzM0pK1NIRcSnlNR3QeZVWAivNNPdmY7RdJv
         spYYr7fMiN7YkCvHoHNUYpJpU+Z4Ly311FHihVfkGgcenTjiZzDCkAZuYuTVXBcrZy3F
         h1mSbY9PcOoKA7xnkr2w7HdKxo3D9n0oMDrYL4RAY7eDN/PZk5ckILaSeaRGnnFORKVT
         dHPye0vKbFswBG4QFU4kNgpf3rsEkW4GHsD7zmIa+K3nfhQLrJZDyNUQc19/TMMImVLc
         YEyg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=zEzk1C26ygRXtNHp2efk7oevBG573qGQW5AEhlokBRc=;
        b=c7p0LtcFeY2BLmL7mOrQRc8ItzLUIqjmcVhp8QK5uYD03rPD9+EqomV9IY9n4WAbFI
         M/yz+VJJqGjn+T1v2tAGRUNS12fB8ZlZQv3nZI+2b0nbQbigkgh5arbudQnLkYRRTAHO
         2F4cxFG/gNdJFFJUdN1FIUSoC6zfrx3Rx+5J7OlKWXHFHL1IM8di+VzqRuXJY5MgWp9q
         iLdpRTnIp04clsPKRyAcvNF+rsdcUrHWo33WTrH8KwrBkBDabBJe15V8VinYTekmDkEG
         la1elwcjJWIwHlANRKmcqNkcXSo6/4SZI9yGF15EQr6NVJVLsu2t1H8gdgFo7qppU+im
         RMfw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linuxfoundation.org header.s=korg header.b=DSyPj5Ws;
       spf=pass (google.com: domain of gregkh@linuxfoundation.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=gregkh@linuxfoundation.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linuxfoundation.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id i14si522345ots.4.2021.03.27.03.37.10
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Sat, 27 Mar 2021 03:37:10 -0700 (PDT)
Received-SPF: pass (google.com: domain of gregkh@linuxfoundation.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPSA id B989C619E8;
	Sat, 27 Mar 2021 10:37:08 +0000 (UTC)
Date: Sat, 27 Mar 2021 11:37:06 +0100
From: Greg Kroah-Hartman <gregkh@linuxfoundation.org>
To: Alexander Lochmann <info@alexander-lochmann.de>
Cc: Dmitry Vyukov <dvyukov@google.com>,
	Andrey Konovalov <andreyknvl@google.com>,
	Jonathan Corbet <corbet@lwn.net>,
	Randy Dunlap <rdunlap@infradead.org>,
	Andrew Klychkov <andrew.a.klychkov@gmail.com>,
	Miguel Ojeda <ojeda@kernel.org>,
	Andrew Morton <akpm@linux-foundation.org>,
	Jakub Kicinski <kuba@kernel.org>,
	Aleksandr Nogikh <nogikh@google.com>,
	Wei Yongjun <weiyongjun1@huawei.com>,
	Maciej Grochowski <maciej.grochowski@pm.me>,
	kasan-dev@googlegroups.com, linux-doc@vger.kernel.org,
	linux-kernel@vger.kernel.org
Subject: Re: [PATCHv3] Introduced new tracing mode KCOV_MODE_UNIQUE.
Message-ID: <YF8K0k1bc3e381qS@kroah.com>
References: <20210326205135.6098-1-info@alexander-lochmann.de>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20210326205135.6098-1-info@alexander-lochmann.de>
X-Original-Sender: gregkh@linuxfoundation.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linuxfoundation.org header.s=korg header.b=DSyPj5Ws;       spf=pass
 (google.com: domain of gregkh@linuxfoundation.org designates 198.145.29.99 as
 permitted sender) smtp.mailfrom=gregkh@linuxfoundation.org;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=linuxfoundation.org
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

On Fri, Mar 26, 2021 at 09:51:28PM +0100, Alexander Lochmann wrote:
> It simply stores the executed PCs.
> The execution order is discarded.
> Each bit in the shared buffer represents every fourth
> byte of the text segment.
> Since a call instruction on every supported
> architecture is at least four bytes, it is safe
> to just store every fourth byte of the text segment.
> In contrast to KCOV_MODE_TRACE_PC, the shared buffer
> cannot overflow. Thus, all executed PCs are recorded.

Odd line-wrapping :(

Anyway, this describes _what_ this does, but I have no idea _why_ we
want this at all.  What does this do that you can not do today?  Why is
this needed?  Who will use this?  What tools have been modified to work
with it to prove it works properly?

thanks,

greg k-h

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YF8K0k1bc3e381qS%40kroah.com.
