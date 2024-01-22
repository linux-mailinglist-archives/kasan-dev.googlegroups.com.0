Return-Path: <kasan-dev+bncBD55D5XYUAJBBGNWW6WQMGQEWYS5BTA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf38.google.com (mail-qv1-xf38.google.com [IPv6:2607:f8b0:4864:20::f38])
	by mail.lfdr.de (Postfix) with ESMTPS id 9A415835993
	for <lists+kasan-dev@lfdr.de>; Mon, 22 Jan 2024 04:03:54 +0100 (CET)
Received: by mail-qv1-xf38.google.com with SMTP id 6a1803df08f44-6854ad24a0csf34487246d6.3
        for <lists+kasan-dev@lfdr.de>; Sun, 21 Jan 2024 19:03:54 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1705892633; cv=pass;
        d=google.com; s=arc-20160816;
        b=vkBeZydsZMzkwVUI7/hIl1/pxQyf7S6AxO2iFFTcnPRYUDzjcyOApF5ul6PdCA4gsb
         61dbx5818cp3fD1DjDA5DghoUbBOFKWCdVaGoIrDIINCvsse30DKYsWPxW9GLv1Nmw7T
         qX4gpVPzDvzoG08XZ5Y6nGzkCuV5ygnxL1ikwC++aDjPINl/UFl1wWvIzneTpt2dh38+
         OhWSkilHLNCABENNzpRNh+8XN4lKl6Rm3oCIUISmDiYEoBv2N8ERtKE7c3aZdf51ypYR
         71vc08JTol7alJUuLukxAxTWapR0eY2TE7bTyBWFiLI4IPcNy7MIWqWp3q1VMBzTj4ls
         zFkQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=sKZO6aZ9QgoecSc6QyYImXo8UuGuS7lRcXZC12kUprU=;
        fh=/n9ysHmfKtxyPIbL6HftWTzXDPJXcCV+9UXmYsFUDPY=;
        b=CDidw7Zz2OkzOI4iS0Okl2AEtx0ERE6SwaOrbV9GfQXCfeea+16b8ss6x5a0LrzFIh
         1BI5vb+kbCPBDJJi++32u55tUyumjbcqsR6rKgMqQOBfJBvYrMHRZOvj+Fm1ieV6No7O
         21pfoNWkKiJQRNNSunAMKCskfHMnNvfWT7rQwOX4Whv1lelxSveB/F+hj+Y3zk7/jwAN
         E+/hya7e5yS4qLrQ8+C6OCYsPsCZMhFrWz8sV0enPNQtfhGi6pwUe3K/e1vcVrEMw/Yz
         s40QALeVLXIZgTmRco0I315J5NKGNMRhlCdisJHfFeHALl1KAiYfX1FJYj4n3Qw20kWD
         oXCw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@bytedance.com header.s=google header.b=cEg3vWE4;
       spf=pass (google.com: domain of lizhe.67@bytedance.com designates 2607:f8b0:4864:20::62c as permitted sender) smtp.mailfrom=lizhe.67@bytedance.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=bytedance.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1705892633; x=1706497433; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=sKZO6aZ9QgoecSc6QyYImXo8UuGuS7lRcXZC12kUprU=;
        b=odTcVLD+hlZ3BX8nqzphy3JZHvCa26LTN8JfibJP/+ZoEe1T+be6i/2FqjqbNVMuJj
         3Uz53XgYugu2d/cGOjYnIzQSGuZDOUr4h1gryrOt0NSiSj1QGdtxsbV+UYqX+tfLBY8p
         kSZGMCfdoydQTV+pXrcZS5uvFbLfH2kYtfM64WGGx9AQYaht5v/ihK83l3VOq4P1ClKr
         3WuH1RQzb+Mf8ivvDwpEGuY0CwOINVD5fFbwiHIcQ4chvmQsEJHZTvNflAfhZMLVYR2R
         eMpxi69xHjtY4zMSgwLuWXjQG6qZTXn1oFTOu58cHoS6yufeHmsfvOI5NpV7+QPvnOY6
         zyAA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1705892633; x=1706497433;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=sKZO6aZ9QgoecSc6QyYImXo8UuGuS7lRcXZC12kUprU=;
        b=fKs79yrq6/qT4GcBgZ1UIiDEjL/RsTTxgVnflUPzc1lB2jldQ5FGiYFhSFpV+KQbDl
         fj565dfqW4Scuip87FSWjxHBvw8DZTZdwyjdjDtpp39Lwj7aJ0ygRvaWnCkgZT7CP2j/
         Swj0JwVvhUX/8P9AnHC2qmYtD0a5kgho3Omko8h820qw0D3zQBMl9X9djGcE2623IMvy
         7yS34mFPO6W3CIsQuab1/hj4gAt148D+wElmgC8sgyR6dxKobvpVeo2OuNgoSDMaRXw5
         RTOX7TZGe8lCPI9wUsTYAId5khBBCbBzPliCo7olkLu9DAQaOT/n/fI0jp6imYyKWepV
         n5ng==
X-Gm-Message-State: AOJu0Yy/3a14OXroi0TfoLsfUpR1hDZ2OQG+bgNktJjnEk47yFUYba8l
	lCMnQRIQ7ZKq0hNyB5bdejk/a+20nBMHAkh08+H2zKazx7E19GSY
X-Google-Smtp-Source: AGHT+IF1wdpBlM/Qgz/BUGyA5tz55pi8tUYhG2+LATZmsUokK7SDx6BN5O1EpqnILR1t5GzKRQVubw==
X-Received: by 2002:a0c:f50b:0:b0:685:f795:def9 with SMTP id j11-20020a0cf50b000000b00685f795def9mr3933936qvm.71.1705892633367;
        Sun, 21 Jan 2024 19:03:53 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a0c:b345:0:b0:67a:203f:dbc7 with SMTP id a5-20020a0cb345000000b0067a203fdbc7ls5413284qvf.1.-pod-prod-06-us;
 Sun, 21 Jan 2024 19:03:53 -0800 (PST)
X-Received: by 2002:a81:6d0c:0:b0:5ff:abd5:99a6 with SMTP id i12-20020a816d0c000000b005ffabd599a6mr2348569ywc.29.1705892632713;
        Sun, 21 Jan 2024 19:03:52 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1705892632; cv=none;
        d=google.com; s=arc-20160816;
        b=GG9ez0C2y0oSqlfTzyle4XG2Sj3+HLL4bWlmaI4tdxBxyW4rtt5JNdqqefxXR+7C1H
         SSOlAcRbTTJKF6orzpvq+zjjxel4Qn8U+6zAOuNECMSXqe2tf92sqH8awKmEccgRPgIl
         fA/joCwII8GeOHs/bmMR0rOGD0AcXajqrUKf1VowcIUf9ZOjBJD4U+MxHptUrDA342+S
         lzw4Ih0D+Ww9i5cwQu1vhn1cZajEFnQqYXYAs/sVPBNBWOpfJlKwB7btA3NmScLD5Kup
         RlpcaRiusAf9+ydPcbRCe2C+I7xKbgq8cFY41FKGqoiQdE58OjGW6vJmZV95R5DK4Y2l
         hwag==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=1GvHKNIqnJM7JEqGBoL8NQ8pCtF/rMhUhETqjEYO1NE=;
        fh=/n9ysHmfKtxyPIbL6HftWTzXDPJXcCV+9UXmYsFUDPY=;
        b=tEBewmMJDNTtp/axdGsNhkhLbqcX+J/+xeArEDJUx4iBRlBn6v2dQ6pLVJXcohyzFG
         +xkW+8yAc+EOjIBrPaoY33uiXKPDdzC3bAzklYCqM6y5ilSeuql+ZKyFYCVmHol1SC2e
         JzTYUrYMPG1r+SPonrqVShGfvCbVDPjhbbzCuVePxkRBcfEPp30dfjT+2O6uBqFm162W
         HnON71QVD5HtD36/M6rC+D4b5vUDwJTbVv+KFGjUahsa/A8HraB7k8F4WIP+1MNe6pQq
         lJCB5IXV3J2aHqqv2MmEA3CyRzxUBxHlI/YaP+uvA12gvoFkcTVKHJthj4B7uQQ3m15s
         C2IA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@bytedance.com header.s=google header.b=cEg3vWE4;
       spf=pass (google.com: domain of lizhe.67@bytedance.com designates 2607:f8b0:4864:20::62c as permitted sender) smtp.mailfrom=lizhe.67@bytedance.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=bytedance.com
Received: from mail-pl1-x62c.google.com (mail-pl1-x62c.google.com. [2607:f8b0:4864:20::62c])
        by gmr-mx.google.com with ESMTPS id y73-20020a0dd64c000000b005ff7aab3b18si967540ywd.2.2024.01.21.19.03.52
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sun, 21 Jan 2024 19:03:52 -0800 (PST)
Received-SPF: pass (google.com: domain of lizhe.67@bytedance.com designates 2607:f8b0:4864:20::62c as permitted sender) client-ip=2607:f8b0:4864:20::62c;
Received: by mail-pl1-x62c.google.com with SMTP id d9443c01a7336-1d6fbaaec91so21549105ad.3
        for <kasan-dev@googlegroups.com>; Sun, 21 Jan 2024 19:03:52 -0800 (PST)
X-Received: by 2002:a17:902:da8c:b0:1d7:504a:c117 with SMTP id j12-20020a170902da8c00b001d7504ac117mr1476431plx.88.1705892631897;
        Sun, 21 Jan 2024 19:03:51 -0800 (PST)
Received: from GQ6QX3JCW2.bytedance.net ([203.208.189.10])
        by smtp.gmail.com with ESMTPSA id u9-20020a170903124900b001d60a705628sm6284506plh.246.2024.01.21.19.03.47
        (version=TLS1_3 cipher=TLS_CHACHA20_POLY1305_SHA256 bits=256/256);
        Sun, 21 Jan 2024 19:03:51 -0800 (PST)
From: "lizhe.67 via kasan-dev" <kasan-dev@googlegroups.com>
To: andreyknvl@gmail.com
Cc: akpm@linux-foundation.org,
	dvyukov@google.com,
	elver@google.com,
	glider@google.com,
	kasan-dev@googlegroups.com,
	linux-mm@kvack.org,
	lizefan.x@bytedance.com,
	lizhe.67@bytedance.com,
	ryabinin.a.a@gmail.com,
	vincenzo.frascino@arm.com
Subject: Re: [RFC 0/2] kasan: introduce mem track feature
Date: Mon, 22 Jan 2024 11:03:43 +0800
Message-ID: <20240122030343.17548-1-lizhe.67@bytedance.com>
X-Mailer: git-send-email 2.43.0
In-Reply-To: <CA+fCnZdVVhx-sNU36A1pa3dJkE_RyYjdJU-PZQf57E42GWO46A@mail.gmail.com>
References: <CA+fCnZdVVhx-sNU36A1pa3dJkE_RyYjdJU-PZQf57E42GWO46A@mail.gmail.com>
MIME-Version: 1.0
X-Original-Sender: lizhe.67@bytedance.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@bytedance.com header.s=google header.b=cEg3vWE4;       spf=pass
 (google.com: domain of lizhe.67@bytedance.com designates 2607:f8b0:4864:20::62c
 as permitted sender) smtp.mailfrom=lizhe.67@bytedance.com;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=bytedance.com
X-Original-From: lizhe.67@bytedance.com
Reply-To: lizhe.67@bytedance.com
Content-Type: text/plain; charset="UTF-8"
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

On Thu, 18 Jan 2024 14:28:00, andreyknvl@gmail.com wrote:
>
>> Yes I am trying to add custom poison/unpoison functions which can monitor
>> memory in a fine-grained manner, and not affect the original functionality
>> of kasan. For example, for a 100-byte variable, I may only want to monitor
>> certain two bytes (byte 3 and 4) in it. According to my understanding,
>> kasan_poison/unpoison() can not detect the middle bytes individually. So I
>> don't think function kasan_poison/unpoison() can do what I want.
>
>I'm not sure this type of tracking belongs within KASAN.
>
>If there are only a few locations you want to monitor, perhaps a
>separate tools based on watchpoints would make more sense?

Thank you for your review!

Yes hardware breakpoint is a method to monitor a few locations. However,
this depends on the hardware implementation and there will be a problem of
limited number of hardware watchpoints, and software solution does not have
these problems.

>
>Another alternative is to base this functionality on KMSAN: it already
>allows for bit-level precision. Plus, it would allow to only report
>when the marked memory is actually being used, not when it's just
>being copied. Perhaps Alexander can comment on whether this makes
>sense.
>
>If we decide to add this to KASAN or KMSAN, we need to least also add
>some in-tree users to demonstrate the functionality. And it would be
>great to find some bugs with it, but perhaps syzbot will be able to
>take care of that.
>
>Thank you!

In my opinion, currently this feature will only appear in our daily debugging
process. Maybe this feature can be used in perf later. Or do you have any
suggestions for in-tree users?

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240122030343.17548-1-lizhe.67%40bytedance.com.
