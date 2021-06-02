Return-Path: <kasan-dev+bncBDW2JDUY5AORBDXR3WCQMGQEU3AQP2Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33c.google.com (mail-wm1-x33c.google.com [IPv6:2a00:1450:4864:20::33c])
	by mail.lfdr.de (Postfix) with ESMTPS id 76F72398963
	for <lists+kasan-dev@lfdr.de>; Wed,  2 Jun 2021 14:24:46 +0200 (CEST)
Received: by mail-wm1-x33c.google.com with SMTP id n20-20020a05600c4f94b029017f371265fesf2128698wmq.5
        for <lists+kasan-dev@lfdr.de>; Wed, 02 Jun 2021 05:24:46 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1622636686; cv=pass;
        d=google.com; s=arc-20160816;
        b=El85ouf6I22OIEiksTuchibTLaiel0ULXozN9VKoQhmdRkCBtAEy74Wp92hZJabtSP
         5OpClcvow2VRgmuD7fnjyUUtarBsz+xEQlgraBaWTXsfYJ/oSDuGUO6rLXY47N4po1vx
         gF4W3KUld+vqTB6jHyooAa7Kpvov9AO3h/yZZwJWYEc/DAw+O3n4wxMr+OBa70JKPHFu
         HhnShZpnHa82bCOlA5ftX31TVvFvA2UXI2FskhEUVvxtMSw40PQA8YxZvYWs+3Dz31CT
         zjhN2pMfzD+0Tz06BEzVCywbN3+lhPq6ACLB8L9xswDOSit9oxfSvROlrKYRQS7icmcG
         ocFQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature
         :dkim-signature;
        bh=lqrCHnCBFIFWjJ0tSDvTYWE1GtxXAe0wmZ62F4xSjNs=;
        b=r1hTV+Pw6+qe/J92ZgNJkEuQGDF7KE/QWaXpBTv+yAlqT8p7QreinTMYTjZAYZsdmA
         V2hPbZzyWv2SLOqxdWiJH2KPEtRzCqzDudwtCmeDv1Budgd7eeDN/m6qF69nGbk2xAcN
         BBI2KAwE+nFpcSdOmjx4YX7jxa59v0H2VSyBhRhOOLsGImiH2A/dIQWhpA7AwJcgX/dm
         2Wj2z4sulcG2hd+/9gFtuAluAwDya+Zu82W9Geo+9Gx7rzXypfOAC/zcLPHd50dCA+px
         Q9eAzyHNbrHt54ow3wGk2xDz84XTVAToSnYplGvVJ8FjCITlbn9xxJIZ1HIswcFCzPFr
         +uCw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=qTe44U4p;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::62a as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=lqrCHnCBFIFWjJ0tSDvTYWE1GtxXAe0wmZ62F4xSjNs=;
        b=fhMlL5V4RB9An2S4eVGVD404Yev4JOebPA1/u8wBxH6XwG/zDAVCo6q+Gyjg3B7NGm
         CquBD4Oui6l/trZf+PUzLbT+TW3SrekLatWKyBSHRSfWVnx/q8hsP3FGY+iQ/w5jrqTM
         hj9favn4+ez+bxk18RO5a82A+rGihruaMNkw0S07+8QoTlAD8ni2pR9WM4CaRQouRta8
         ulvKDl4r/xL/HJjlUASxPOX4cL92GqqfapvCYoDsxWTd8SyRhpgzCMQ5VxNzpwWb3kSx
         Lltbgl5rY9Kg/o3nrEPbRTZLjm9+BBDqZq+5YPgvWVqAsC71wrrptdlcF2HhjniN9BPC
         OhWA==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=lqrCHnCBFIFWjJ0tSDvTYWE1GtxXAe0wmZ62F4xSjNs=;
        b=etouHC01U8pdvFcnPYd99EYIKXN+1FzExTRQyGokz+vd0nIhwRLAny1nFXyuImnnvk
         OpGm6+ZZ+JPzctYhWd/BvhBeBIGE7ujG47oOYwK55nKUaLXa9rAH+E5BYrxKvWuhL8UY
         +iYikaTq7Ttn1ZS8hBQb9WsEaPxl2BsRqW0eWejlAr0Y/8WnvwPbWCABBwOczntplHR2
         /2vAzdgBeYkHZs7pyb4RFDw9ZpL38WY/ass/HDKEnDA4i45Me9cjAk6BoMhPjoIz6UP3
         sMaMQb7RRJcnYNXDKtV/5+TBc5OM7rWibNClKa12SpVSiWu8J0MBrbaul17PDzqZCF8K
         Seug==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=lqrCHnCBFIFWjJ0tSDvTYWE1GtxXAe0wmZ62F4xSjNs=;
        b=b26K986c+ezmmN+zZvdPqp8rOIpk98C+ukeL7HLJCv34lxHe7teMklLI9EF3uc9Pl8
         rL5cMq6DlzD0Tk7FvYEh9vjcHtmpf8u4304fgC+kAO6SiaIXBA7bVlfqf9Wb8f7LxuWe
         2pkmllIxp+16P8aHGZ2PWgJpAVwdtzqfSoQiqJI23Qo27vVx2+8JRm9b5btb1+YAvbSn
         DWvlZDukoZKp0dZEbKUcJ2UzHZUJK8i2J6eHnxW4uQT2oEL3c4VLhkNx1sVphfvGuJlb
         dGvPflyQDynhtDh5gTCeT1C7QlpiWzU2Z8vW8fjOC6rRvR7T6SuMphB+ckE4wtjv5kxP
         6YNA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531pAoVeVo0xN5IPp5+ZIy9u3F8oJpsj5rSTp22aNUVsk1mwqQwA
	xYWzOqu8FUCGhxsrTS34KQY=
X-Google-Smtp-Source: ABdhPJzR5YfqC0aw71qKtlY2ng+VqAyJFTXu0P3ySEd1J4/ILfW2xRxqsDYEOMJ+z32dErRi7kQfZQ==
X-Received: by 2002:a1c:bb45:: with SMTP id l66mr4931329wmf.29.1622636686194;
        Wed, 02 Jun 2021 05:24:46 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a7b:c0d1:: with SMTP id s17ls18373wmh.0.gmail; Wed, 02 Jun
 2021 05:24:45 -0700 (PDT)
X-Received: by 2002:a7b:c247:: with SMTP id b7mr4928598wmj.99.1622636685405;
        Wed, 02 Jun 2021 05:24:45 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1622636685; cv=none;
        d=google.com; s=arc-20160816;
        b=DE+oaNA9oHih2d9RH+cTVPnOZdzR2Q6w9rYNkjniyLnflVXX2Jf8qqbaeA0Lyk1ZN/
         D6466+BRhPUPJd5wfYVnZ79XEr0msjMuAwg9uwdQDLWQFjD1IbiRgGsxjKj4Y+fQkrSm
         nm6nYP2nU9auLLLv+V/JxdLIfkZErq03y6q17002/VZBrYGqi3mDaCJaqj9CD5nwQ9LB
         0ElmKWZfVoHmDuGVeff0dvD+Qw+KOymub5O5SiHdDCXXjgaHxcWoRkVrmx/RD94u1UwN
         jC4H97KLzLsziajlUmlGceYQqy48hP/9WhTHnn4OsM+ZxYGXe7S5Ki8P6ioy+W8NJsNB
         X4Cw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=AwfKJOjaR7R6vzUo1s6BF5wo5oy1/Uxlj9t1SzL/r6g=;
        b=MX800prtkJ5aWiDpcZdesNqfHnQByTjJaVYZ66STa/kwJUIlrb3jgF17FyRPnr8adi
         fbNLe4HyAzy6nd7+pYM5vRJukYamDfR95ACSUw0p4X9dVSCoGObTS/yQ9wW26wNuYOT/
         f1jN+qNC9r+Ux71NBvhmIpCXzB8XySsLU+LQyqCo65P1H25mWRg6Z/2fGXUBsQpHSmIJ
         2ge8PFVtaMAxaFa7OMe0Kip61GrKxzwR1xqvl5Slo38NUJSXiPnqhineMiEpXDr+tszK
         6gNNZMC58Lf3l/rf/1w7G02k1GgqiNM/mSOLP/1DETGvq/NQiNrIROpYDgGot+sowYiB
         u+mQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=qTe44U4p;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::62a as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-ej1-x62a.google.com (mail-ej1-x62a.google.com. [2a00:1450:4864:20::62a])
        by gmr-mx.google.com with ESMTPS id t1si431435wrn.4.2021.06.02.05.24.45
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 02 Jun 2021 05:24:45 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::62a as permitted sender) client-ip=2a00:1450:4864:20::62a;
Received: by mail-ej1-x62a.google.com with SMTP id qq22so3524620ejb.9
        for <kasan-dev@googlegroups.com>; Wed, 02 Jun 2021 05:24:45 -0700 (PDT)
X-Received: by 2002:a17:906:a945:: with SMTP id hh5mr33928412ejb.227.1622636685254;
 Wed, 02 Jun 2021 05:24:45 -0700 (PDT)
MIME-Version: 1.0
References: <20210530044708.7155-1-kylee0686026@gmail.com> <20210530044708.7155-2-kylee0686026@gmail.com>
 <YLSjUOVo5c+gTbzA@elver.google.com>
In-Reply-To: <YLSjUOVo5c+gTbzA@elver.google.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Wed, 2 Jun 2021 15:24:34 +0300
Message-ID: <CA+fCnZdb_eueAqG_Ka5-ea3EurG4oCmFCQ9Zd+d1O+BvkdNXnQ@mail.gmail.com>
Subject: Re: [PATCH 1/1] kasan: add memory corruption identification for
 hardware tag-based mode
To: Marco Elver <elver@google.com>
Cc: Kuan-Ying Lee <kylee0686026@gmail.com>, Andrey Ryabinin <ryabinin.a.a@gmail.com>, 
	Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Andrew Morton <akpm@linux-foundation.org>, kasan-dev <kasan-dev@googlegroups.com>, 
	LKML <linux-kernel@vger.kernel.org>, 
	Linux Memory Management List <linux-mm@kvack.org>, Walter Wu <walter-zh.wu@mediatek.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20161025 header.b=qTe44U4p;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::62a
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

On Mon, May 31, 2021 at 11:50 AM Marco Elver <elver@google.com> wrote:
>
> On Sun, May 30, 2021 at 12:47PM +0800, Kuan-Ying Lee wrote:
> > Add memory corruption identification at bug report for hardware tag-based
> > mode. The report shows whether it is "use-after-free" or "out-of-bound"
> > error instead of "invalid-access" error. This will make it easier for
> > programmers to see the memory corruption problem.
> >
> > We extend the slab to store five old free pointer tag and free backtrace,
> > we can check if the tagged address is in the slab record and make a good
> > guess if the object is more like "use-after-free" or "out-of-bound".
> > therefore every slab memory corruption can be identified whether it's
> > "use-after-free" or "out-of-bound".
> >
> > Signed-off-by: Kuan-Ying Lee <kylee0686026@gmail.com>
>
> On a whole this makes sense because SW_TAGS mode supports this, too.
>
> My main complaints are the copy-paste of the SW_TAGS code.
>
> Does it make sense to refactor per my suggestions below?
>
> This is also a question to KASAN maintainers (Andrey, any preference?).

All of your comments are valid. Thank you, Marco.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CA%2BfCnZdb_eueAqG_Ka5-ea3EurG4oCmFCQ9Zd%2Bd1O%2BBvkdNXnQ%40mail.gmail.com.
