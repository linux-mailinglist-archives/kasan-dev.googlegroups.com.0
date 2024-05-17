Return-Path: <kasan-dev+bncBDW2JDUY5AORBEGAT6ZAMGQEYU72MWY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13e.google.com (mail-lf1-x13e.google.com [IPv6:2a00:1450:4864:20::13e])
	by mail.lfdr.de (Postfix) with ESMTPS id 011048C8E5C
	for <lists+kasan-dev@lfdr.de>; Sat, 18 May 2024 00:54:10 +0200 (CEST)
Received: by mail-lf1-x13e.google.com with SMTP id 2adb3069b0e04-52025c91485sf8379440e87.0
        for <lists+kasan-dev@lfdr.de>; Fri, 17 May 2024 15:54:09 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1715986449; cv=pass;
        d=google.com; s=arc-20160816;
        b=aGOHSqdUy9YssNXfCDVl3Ho7Xjgwkd7ztDik6h7boBP2dt47PYkjzo6UUzwd0+YKRt
         h/ZlIifM3pOlkW54jJ7NFtEQK6KNNIy/bxMwX8J1kC+u8iQHQ+Lr2wiSyLDDGiaoIdA3
         IgH5r7BQqjMa/b4NApmWgwalJyxRvxIVcEzE+2DTBJzWyHvMk2O9N1hBr4TCSkWNUOV6
         hy3kjNxHqoGsF9eypzJ2btqgBOLS8Dc/5NVosIlcvfhEgF0tw8kGQrtw8pNINB8Db2ac
         7ZinAOkhCavfqOknKLzWyem/oLW9ifSsuezMjHwp3YNkNbP/2Ah4kn3rC6Z8OVQkMn52
         tVNQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=v0c1NAX2yaNRkyoCL17XUBkpx1Ng+TV7deccKNgKxdQ=;
        fh=F62isPqj4MaiJPrRuYG9Fp9gcxTexqj4YkgWIyZXMX4=;
        b=Ke6vuQnm66PFRqV0Pe5/zWqrX7i5VIrE/NKOLCnmKdIFn1v+xUVgb2lHcKPzAqIOYe
         GnmWEbas3v2CqHWlJ5mRu9aKSLlsjB+4perfuXWjXU6YVYs8QYGnqFM4Kv/Pq9cTV3fH
         kjBlWf/VKZHOQhJqIR40SFTsKfLf//wFBRQwHVyrE+u8PMhFsRiH+2ZvJm6pmQe0WxWs
         jhxJyrVd/1/h7XIDTb71MTNOT9Hcq4CM2Buh1B4b09p+xGmkI/S4W+MKkHvTknWU8IOn
         SvvIhBpnUZm4mftx3PtZ9KKQPvlyVGv1CSGeAx/vvX1l1lRMEnAM5PsX7qRhBg8L94gR
         nedg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=DfCOZLZf;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::42f as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1715986449; x=1716591249; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=v0c1NAX2yaNRkyoCL17XUBkpx1Ng+TV7deccKNgKxdQ=;
        b=Gu4x2s+4FYauEJPGd0HEmIbdeg4m6yt5Rlxo/7uNeepTGQY4zUu9kO1QieiKxyvHxO
         eksdG/MC+lpm8tQHkZrIgGEz4f5HT40087OGWgl+51WS0yzFKTTPMaTxiEeYwLW0YC7d
         LV9cq5TISeJh0P2iz/I1/rhw9Qe/ReTdK1JXYOMej44FE8o+Smh9PJTLEq5ubb5trf3w
         bNZL7x3KwOepG0HKE5G10s6Si/oH3mdspdbAR9SHRxN27BugQl7ypKt3SAFiP4prN06E
         a4lqE3rSTZ/u60FsH7MWNKP+BtZUyO0AcB5MoYuk2KIRXT8d9H1oMVmz2qdb8wkinxg1
         L6bw==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1715986449; x=1716591249; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=v0c1NAX2yaNRkyoCL17XUBkpx1Ng+TV7deccKNgKxdQ=;
        b=I01vB3WWpy1FKC08zYZ51KROfO3C2aGVQy5PnHdXddAB3FCn1QCJSN6kAo6AJRqK8E
         IpQ6s0LnUvvXQI+E0gttGheKiYan1oYLofPujBMv8x9leGrqHRaz6xMHEzMbpkkSn+L/
         0SVOu+gskq8C2JOQVZwSw95ELVvh6BRD089HXWFoGmHFnut9LZFGKgsZV7HS3TFbH8zx
         HTP4o6vMpaSgqBkWGuWCG0EIWUoabQY7oaTcJD83alLsyg8yL23xcyVFKkVuJB1cGXfQ
         gD+xGwH1vw3MrVmLQUs2gcsVKoZmype+Z9u3wVZBEEnWpWKuAoHPH3pUinEAeCfTI91P
         9Mog==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1715986449; x=1716591249;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=v0c1NAX2yaNRkyoCL17XUBkpx1Ng+TV7deccKNgKxdQ=;
        b=uV0IS5f0dSdmd5yFSqZrA6CM05aEyEb8DOK8UGhOc4bwdXz8gdPmqwI02mVB9Ti9qS
         iv9bDYVCS+7WbCtb+z+OIFDOS+B0c/gpNp+g+KYCrnR7JtHdUd9VIFeU4OtHX0aPrW/u
         gOBr5/69aOzjVRvvuW2whYXpD3Jg1HjKIETFzm2DlRK57W04ugZp7gzT1ny18yaCHUkC
         PamWU3174WKcKBBLRXFwYyOQen5sPHNX9Z2gkwiJOg4DUNL+lZf3zJvsU2xtSr5ja4pW
         6RDMFaD9mJ8YFqiQ5aXYHkKywSlT6HmzBqxEnxbNv3ojiX+YVUNEXancVgICbquQ9aNu
         jxNw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUEFfbQ9ZJ+Cd3PCVThM4I6eoNuosl9Je6YG8Hz/HNosTA+a6nho1CzErnwz1WAAgKh/Vc3uaPA0B8dNh4rd9ADdxnO48GFUA==
X-Gm-Message-State: AOJu0Yy6BYF2yh217TX0A0LkIsKPjwONkG6hM84lWYMFTiR0xlzmTQoV
	W7FnQtRslsf4gLiDKgMD3xykDqr/dYZLn6DGOblMIuyxy8dQpjwI
X-Google-Smtp-Source: AGHT+IHF3Wb5DROQv4CWqFwM4IgD3zovLK/IfJY+BUE8i7DMmCFeOX+fO+6BL56OBUGUZyN7apX9Bg==
X-Received: by 2002:a05:6512:783:b0:51b:214c:5239 with SMTP id 2adb3069b0e04-52210275f25mr13693953e87.62.1715986449128;
        Fri, 17 May 2024 15:54:09 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:3b8a:b0:51f:4a71:1afb with SMTP id
 2adb3069b0e04-521e33409c6ls468848e87.0.-pod-prod-09-eu; Fri, 17 May 2024
 15:54:07 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUCyrnIMB7UsDmO0s1FPb5lSigcTjYCudZheURtTNm93qubl8th8l4I1muO9gqswVR8HQrjDHNDSXb4/Yusf2ilYX9fxaE3wyjP8g==
X-Received: by 2002:ac2:596a:0:b0:523:a5b3:5e1d with SMTP id 2adb3069b0e04-523a5b35f2amr5042552e87.10.1715986447014;
        Fri, 17 May 2024 15:54:07 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1715986446; cv=none;
        d=google.com; s=arc-20160816;
        b=GeXdpn4ANb2ogv8RClvguTYFAs1K5XpGkhii0M94EudZK/49DxweATzTmnoZ6fJB1m
         0SKB06bMNjMPPs2XYBMLDdLU/1+tGvz98oQzGcwnxU6cHhw4ECmGP2RnESvWX96cHbyI
         bhveJz/yxT5bvzqP+eVeenKhm+iEYVGyiIl8Z7pWKaSolXFiDpH7Riy5Ljmel1+JBLzs
         xJe8O3qdnSKpOJtR2NWlPYmpZVHc+xagv0ZgQrfqr0GOYgWqzz73sFuKwQTgSVNP0Zqk
         jlV99t398qp8/0a+teL36QRa7pDyf2vzlWmB3EU+60yxkc2jGyFwktqO7y+dewqMdnrv
         4+RQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=Qz6Q16/VE6yW7THwpXy9wA+z2fX/PLFAUPnbPAQU51o=;
        fh=5KvBYn9mEj33Y+iQCs3vpc1WGYGJZIfKQfu3K4zoawo=;
        b=nhxBbNRANSBWeHckI35Q80LcPvfIqejxGYoYVaLv+BJ9SB+zKc9a+YaTJl6wroX0lj
         /0hCjzANSkmkt5WLwGnOuE/lZRiDBafLbN7yqz5M5+wG0X2z8GQjtP+AM32OVG1OppFw
         MFBH+8S2N/SG20wNtSzSmwnOBaMKaQt2HyhzSFskwEdkkc7AQpwmiOC4P/V39JoDsG7L
         hTb3U/+thQGDjrL85iUGrFCwQFSCUCAmhbvPD4r7SG+m51NQVhpCLhpwJrTn5Ry1FC3t
         n0xUOhPb2plupU45GEt/+k16U3D9k4daeQL6eTt9IRAFx9hKg5FnQd1ARLiIPP7PorEu
         Rf0w==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=DfCOZLZf;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::42f as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-wr1-x42f.google.com (mail-wr1-x42f.google.com. [2a00:1450:4864:20::42f])
        by gmr-mx.google.com with ESMTPS id 2adb3069b0e04-52234425109si397609e87.6.2024.05.17.15.54.06
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 17 May 2024 15:54:06 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::42f as permitted sender) client-ip=2a00:1450:4864:20::42f;
Received: by mail-wr1-x42f.google.com with SMTP id ffacd0b85a97d-351d4909783so553817f8f.0
        for <kasan-dev@googlegroups.com>; Fri, 17 May 2024 15:54:06 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCW9KcoaZ/cKpmagvKTubdjMFEPxTUFoDLZECXr/DG73Rt0jagCAqgJdZRbtq0+M7zj46tcDTxibNSERqDLrcc9e8pxUhdnkWPvS6A==
X-Received: by 2002:a5d:4d43:0:b0:345:5f6a:cbf7 with SMTP id
 ffacd0b85a97d-3504a7376a1mr15203162f8f.29.1715986446121; Fri, 17 May 2024
 15:54:06 -0700 (PDT)
MIME-Version: 1.0
References: <20240517130118.759301-1-andrey.konovalov@linux.dev> <CAA1CXcAdG=OFkBzjPqr7M_kC7VZUdj-+vH_2W4UidfbQwfQbeA@mail.gmail.com>
In-Reply-To: <CAA1CXcAdG=OFkBzjPqr7M_kC7VZUdj-+vH_2W4UidfbQwfQbeA@mail.gmail.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Sat, 18 May 2024 00:53:55 +0200
Message-ID: <CA+fCnZeSq0E0SoDOWAEs=ZTYFDZnT2Ox1X5CG1gQC0i88n8WQQ@mail.gmail.com>
Subject: Re: [PATCH] kasan, fortify: properly rename memintrinsics
To: Nico Pache <npache@redhat.com>
Cc: andrey.konovalov@linux.dev, Marco Elver <elver@google.com>, 
	Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Andrey Ryabinin <ryabinin.a.a@gmail.com>, kasan-dev@googlegroups.com, 
	Andrew Morton <akpm@linux-foundation.org>, linux-mm@kvack.org, 
	Erhard Furtner <erhard_f@mailbox.org>, Daniel Axtens <dja@axtens.net>, linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=DfCOZLZf;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::42f
 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
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

On Fri, May 17, 2024 at 9:50=E2=80=AFPM Nico Pache <npache@redhat.com> wrot=
e:
>
> Thank you for fixing this !! The test no longer panics :)

Awesome, thank you for testing!

> Now that the test progresses I also see rcu_uaf failing.
>     # rcu_uaf: EXPECTATION FAILED at mm/kasan/kasan_test.c:870
>     KASAN failure expected in "call_rcu(&global_rcu_ptr->rcu,
> rcu_uaf_reclaim); rcu_barrier()", but none occurred
>     not ok 31 rcu_uaf
>  I can open a new thread for that if you'd like.

Looks like something else is broken :(

Unfortunately, I failed to boot a kernel built with the config that
you provided in QEMU.

If you can provide a config that boots in QEMU or instructions on how
to reproduce the issue, I can take a look.

Thanks!

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CA%2BfCnZeSq0E0SoDOWAEs%3DZTYFDZnT2Ox1X5CG1gQC0i88n8WQQ%40mail.gm=
ail.com.
