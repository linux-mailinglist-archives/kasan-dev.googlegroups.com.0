Return-Path: <kasan-dev+bncBD63B2HX4EPBBTNM4T7AKGQEFEAFLCA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3a.google.com (mail-yb1-xb3a.google.com [IPv6:2607:f8b0:4864:20::b3a])
	by mail.lfdr.de (Postfix) with ESMTPS id 107D12DB4C0
	for <lists+kasan-dev@lfdr.de>; Tue, 15 Dec 2020 21:02:23 +0100 (CET)
Received: by mail-yb1-xb3a.google.com with SMTP id x17sf9163121ybs.12
        for <lists+kasan-dev@lfdr.de>; Tue, 15 Dec 2020 12:02:23 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1608062542; cv=pass;
        d=google.com; s=arc-20160816;
        b=LBxLoRtklkTnrZf04GERgjop6yLAC7+hgTO5WyPAl34f63JWhA3k7AHJy64vlw7Imj
         lAFGYxtZ32o3hyTYn3fUzO3V6jDz/PLenJKJ9WoB/695vxnQ26HsUzDO4AvcT9ff6RZj
         uYsf8UVTpPDW9SpLY7gLWbQkvDvdP6EJlsyfdN592o2njeRp7Gw6f0USc5/ym+6yDmCF
         KhAukRZJHPEcJIKVUw5610wHSiTAHHbUw9SaYd9ZXLB66wFJjYvVWoAzKnYhqBDYWByK
         Qvya9b9u40Avk1UaqvCWJjH8GM+f3rTAxFDy2HFzCo2I4Pcx+CRQlCGxUKAi5aLpZlKS
         KXjA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:dkim-signature;
        bh=p59PeIcaadWvzc77JIO6gdQXDC8i+K3/whs2sE0PObM=;
        b=xXvvqBiAEyszIhVydfIG9mU8drzwB2Sid9c95pA6uxhW2ZzChcNoF7l3WM8WKmDQgI
         Hj/Wdw6/KT9n2mWE7T70PqFe/Sgag3FcAMPYYLLnxkcntBfPPp2s0lHWGe7rIPLiTPQA
         XlYgn5wBsaZNU7XHXGdEdykBk54Ko3IEWPYTBQvfDmh1bHsG7yy7UPvFGnPW/lw+9iOA
         s0lxxoJ9sEHC48iDeVOFmwA1pLykK9UctJAxIKDUZ06TzvECaUqjkHYj2/FfrSmmieoQ
         zbGnOQxWueWixlkYkPMqLn9+2DDcOyJU02vUZfO45hFIfjV3kwqy4gO320rgxkv+ZOp5
         LFMg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@purestorage.com header.s=google header.b=R2JQ3kgO;
       spf=pass (google.com: domain of joern@purestorage.com designates 2607:f8b0:4864:20::436 as permitted sender) smtp.mailfrom=joern@purestorage.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=purestorage.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:content-transfer-encoding:in-reply-to
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=p59PeIcaadWvzc77JIO6gdQXDC8i+K3/whs2sE0PObM=;
        b=YAl+gdPdcvgzq8DFZBk5Awvli34zEtZI4G0b0/sFx0Sa/JLLfj6UGuhw3xpdsy29sU
         jvyu1w9IzpWuOvHSPuZ+0ptvAqV0iVDxx+RaUKcH330OLoEDKMw4hVni5IdBDrc6ghLQ
         pJIUfSb+HJhBAT1nYWsy79WWNZN6puKrMfbXxXimZswP6md5MCBRP2pg04LRKFmN7try
         JHkAS+lA8MugMTJta2kryjsv0Z4yZLjNULWN6V2UaItf3zrcmnNtrp3m72bDVji0DvIO
         uErPaGy2rkny98Pc04FpF2C7U1oP4smR18jaiC1mb/M7/F6EIImlGm9Mx1ztxvbXONNC
         yFOw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:from:to:cc:subject:message-id:references
         :mime-version:content-disposition:content-transfer-encoding
         :in-reply-to:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:x-spam-checked-in-group
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=p59PeIcaadWvzc77JIO6gdQXDC8i+K3/whs2sE0PObM=;
        b=YsSaBAXmxTLgqrDCVpL/fCtu6yFHnZ3UydukdSomLguSk5CogIU0sYBjfB81Ek7Bl8
         aVD56T/vly0QBxZ1Xga5+cV0MKmE84ExJLN7SqGrWFm0AWTaBUNcK0P72YdmnO3Yoq3l
         HUIQlunkeThdLDi+sr33jGkGKO+39sq37sIO3VPqrx2JGQryG9Sf+skKRrptaNxLjNxs
         sakfjBQk2322nGCIJbVgCMShOi9U6wlBz/ILppwxx3dewgNluvsqoP7v9Q6W1EUTwMqq
         3PGStXHHci/FcFAO3vz9hKxEVDAcEUDeqa2gLfRMqKb/U2yd9XXt63vPPljLxi1JbLFw
         Q0tA==
X-Gm-Message-State: AOAM530Ocfjz0XsSns2X22Ur6pJ+dpeIzx0cr00MAD1PBUfV4Q7uHmS0
	UeXqrMO99+zhLR0YBhO8HKg=
X-Google-Smtp-Source: ABdhPJzOZEFXHo/fTVFmEkKoPrL3Rt86lbKf3W5/rfFIUeyjaEk5JVoDgxU0MA0NBe+qK5s8FHk9OA==
X-Received: by 2002:a25:7909:: with SMTP id u9mr42972830ybc.333.1608062542189;
        Tue, 15 Dec 2020 12:02:22 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:20e:: with SMTP id 14ls10595162ybc.0.gmail; Tue, 15 Dec
 2020 12:02:21 -0800 (PST)
X-Received: by 2002:a25:3211:: with SMTP id y17mr44815468yby.301.1608062541599;
        Tue, 15 Dec 2020 12:02:21 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1608062541; cv=none;
        d=google.com; s=arc-20160816;
        b=H45+GWFNA8f+vAs2JDlwsXj1UBFnp5hRgS5jNhrnD01FluIlUZs8cZhajwskLHhKGY
         gs1r5Co//pz3xUyDHvM4/s6qdeydLHHN7s2jPvO8+01pisWzIkpuEihsdx3m1jRX/wJX
         0Nk8mVzJr7UedWdUIzjNmam9K8M6NHJZf4VF0ejEH6P4tYYKw3aAoYLDahhbt9IxtCIH
         3ItWZEIKLQcxgPCa6iJE9LjyHFM/eswNope1RIzkfukor42X9v28DQNdeNP6jmuJDoTW
         G5NPTiQmiF/068TaL44D/PSxg+AaTH0/DMTkIFiCuQNrVIqXgN5yzl5xfF6G9jJxfXAj
         FpVQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-transfer-encoding:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=X+r2uqFvWlmRnUY2PRxx5HpmyieJ3fZ1jksvJTSGbvA=;
        b=MeNXeUH4TuBrv9PYqaF1OHdRESUri3rrVtR6a5Jfl5O8qDJa+Ka0NjOkNupRd2LdVD
         ux5L9fqT7nhCB/m3IU5Y0qZKTUUpOYNFljVxbxwPnDVTsyhwU2gUeQJkUmJ2tssiDcP6
         Jc4X2yzctqlLD4X8wLDyibm6kIdgjYg60f633sC2HfOsHsZzz1cL3+Mt9DVPamBaw/KW
         TZcOp/NKNmeZhGzJvOFxcEkCjtdEfLPS/7sGYhp6+U5H4cpzgFdtsHNQBkzC3n2p6llO
         kZmsuRy2k5gOPB50kheac8O8VOgrr1V1EF8xjSOlgOaoh4FpgE1vQgx+nPTXDcFOjrDN
         qpow==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@purestorage.com header.s=google header.b=R2JQ3kgO;
       spf=pass (google.com: domain of joern@purestorage.com designates 2607:f8b0:4864:20::436 as permitted sender) smtp.mailfrom=joern@purestorage.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=purestorage.com
Received: from mail-pf1-x436.google.com (mail-pf1-x436.google.com. [2607:f8b0:4864:20::436])
        by gmr-mx.google.com with ESMTPS id e10si388812ybp.4.2020.12.15.12.02.21
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 15 Dec 2020 12:02:21 -0800 (PST)
Received-SPF: pass (google.com: domain of joern@purestorage.com designates 2607:f8b0:4864:20::436 as permitted sender) client-ip=2607:f8b0:4864:20::436;
Received: by mail-pf1-x436.google.com with SMTP id m6so5420641pfm.6
        for <kasan-dev@googlegroups.com>; Tue, 15 Dec 2020 12:02:21 -0800 (PST)
X-Received: by 2002:a63:531b:: with SMTP id h27mr30158719pgb.371.1608062540876;
        Tue, 15 Dec 2020 12:02:20 -0800 (PST)
Received: from cork (c-73-93-175-39.hsd1.ca.comcast.net. [73.93.175.39])
        by smtp.gmail.com with ESMTPSA id f9sm24541261pfa.41.2020.12.15.12.02.19
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 15 Dec 2020 12:02:20 -0800 (PST)
Date: Tue, 15 Dec 2020 12:02:17 -0800
From: =?UTF-8?B?J0rDtnJuIEVuZ2VsJyB2aWEga2FzYW4tZGV2?= <kasan-dev@googlegroups.com>
To: Marco Elver <elver@google.com>
Cc: Dmitry Vyukov <dvyukov@google.com>,
	kasan-dev <kasan-dev@googlegroups.com>,
	Alexander Potapenko <glider@google.com>
Subject: Re: stack_trace_save skip
Message-ID: <20201215200217.GE3865940@cork>
References: <20201215151401.GA3865940@cork>
 <20201215161749.GC3865940@cork>
 <X9kAeqWoWIVuVKLq@elver.google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <X9kAeqWoWIVuVKLq@elver.google.com>
X-Original-Sender: joern@purestorage.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@purestorage.com header.s=google header.b=R2JQ3kgO;       spf=pass
 (google.com: domain of joern@purestorage.com designates 2607:f8b0:4864:20::436
 as permitted sender) smtp.mailfrom=joern@purestorage.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=purestorage.com
X-Original-From: =?iso-8859-1?Q?J=F6rn?= Engel <joern@purestorage.com>
Reply-To: =?iso-8859-1?Q?J=F6rn?= Engel <joern@purestorage.com>
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

On Tue, Dec 15, 2020 at 07:29:14PM +0100, Marco Elver wrote:
>=20
> I'll send the below patch with the round of KFENCE patches for 5.12.
> Not sure why we didn't have this earlier, but I guess we were busy just
> trying to get the basic feature polished and these details go missing.
> :-)

Nice!

Then let me see how far I can push my luck.  For an unrelated debug tool
I've decided to finally sit down and write a stack dumper for userspace.
But before I start, maybe you have already created something like that
and I can save the effort.

J=C3=B6rn

--
Journalism is printing what someone else does not want printed;
everything else is public relations.
-- George Orwell

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/20201215200217.GE3865940%40cork.
