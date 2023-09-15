Return-Path: <kasan-dev+bncBDW2JDUY5AORB5EWSKUAMGQEYNPO6UQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x137.google.com (mail-il1-x137.google.com [IPv6:2607:f8b0:4864:20::137])
	by mail.lfdr.de (Postfix) with ESMTPS id 27CDC7A23EA
	for <lists+kasan-dev@lfdr.de>; Fri, 15 Sep 2023 18:51:02 +0200 (CEST)
Received: by mail-il1-x137.google.com with SMTP id e9e14a558f8ab-34e21aae2acsf18953425ab.3
        for <lists+kasan-dev@lfdr.de>; Fri, 15 Sep 2023 09:51:02 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1694796661; cv=pass;
        d=google.com; s=arc-20160816;
        b=isqtO+1xnmN0UO8PoiXKXvNpeiBDALyWx1Ndq81/z6k0NFuZehNzO0xUnVzxXIE3t+
         F06PmPKy+1aluXMqUwW/DpzCzCHi6CFwX8ii1MUd7KGZ0+DNhYhq6OmJoTojwLeSJ0dY
         Z/JPz5/kI1vtdNEuP6xBaCHqUS3gnjt0d9ceQJ8E1gfdnEY1TaLHpZM1dXTkZkK4cB7H
         1Gunesgh/ZPWOo5WsssMsZbcVyfrazeSBm/Y2K3XyrgfkqMkQbgN16PIGp0S4HYlZFOU
         Gar+WjWI0tHwukHhlsAkuls0bOSkmAeQG5JZnW/WnQOWEQm0RnJbGDnwH+OgJdR2D80m
         BhkQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=FtweviR09kA2wgewNgbNCk3zO3LpWe+T0Bw7WWKPdQI=;
        fh=K06HltD1s8cLQtWqVooCEx8EITvFUygkYMCHJkZOESY=;
        b=FwEzNChO+4dByoe2V0l1RMZo+KOF83syzifIUsyxtypMxN3oAinqsPTdTK1Kfi7SNC
         qcazrs0gPh3osGecY2UKOPiXqZ/uKy8sGhFd0VzheN7XmTFg9IPWgd42y3KyYWuzGaE1
         4Jcg+P52vZ8Ip8C1gceRrBx3lL2Curd+jotGX/sTEDG6/aOvre/eyrnFJ3/86dQBM8hI
         8o4tVtxgo8JCg6bb1CZdQvy13IlwMwk8gtNBqST18YD+qFi8MvzLpLuHmfw6Ack3s5io
         szGr4BLhOF4i9nTENBxV5elYNRFiSIbVE2mbB3HVSM5Pk9JvyRzVYsJjOfgIOecCWVNF
         vi4w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=eqAegjm+;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::1029 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1694796661; x=1695401461; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=FtweviR09kA2wgewNgbNCk3zO3LpWe+T0Bw7WWKPdQI=;
        b=pbh1ebEieOn2mRtZ8ty5F08oeWTRFiwWE7ADJ/jZN+M6wD4JSNq4c/Y/m+eGzrLsl9
         JvJtihTyRP8PBP2X6Y+C2DpGzt8/SecJCq2I7qcsvBIJ40eH1KZjrt7Sz371KSRleefG
         SxrokZub0Z5Wx++IVKTSUs2KNz2TNOM6PCxUNcuXp9rXmCFBU309LaTTYmCKwJOIrsrx
         GOueWtLgSmliAVgOaK1Ftp1bMR4DwQpkjEL9/Mb+tyNvOrgMlWvTJ071k1+xSKkPerCS
         0dnK+kIY4U1XR5DVUNwPcjf42smoLlXnQDbAc08h+C5tabvDTTShqlH2BSjQkxRH7zvq
         9p+A==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1694796661; x=1695401461; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=FtweviR09kA2wgewNgbNCk3zO3LpWe+T0Bw7WWKPdQI=;
        b=kLik5IssLcBoD5ZPngor6iZYpsez30tLGJtmsr7zJNXOhkFeiu0MxwAQeEu7mFhWDW
         5pf/f1S9u5UBDvTItydzIODqPrBml/8Fcp5rJDkjfDDdVj1+66GAMEhHXu4yT2Si8V67
         YH9sVN8E7B7CK2d0rr8amFtWw31sRT4w9pzVwD/vAUOIpA1dyz6SOm7yYt5YG25B7fh9
         /OX+9u5gDOB/KADk0Cp4+gNsh2DudMedwgBUMOeGjSk6MEC91aAjHB1bZcczsm6faK4/
         Jyt5VG6GtN3ChbcMlo9iJD60bMnBBRua4XLxRSXsOLnANC/Ujv9x5ucyNQIBIs0bV+p7
         dyRg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1694796661; x=1695401461;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=FtweviR09kA2wgewNgbNCk3zO3LpWe+T0Bw7WWKPdQI=;
        b=b8RqcV80WC/+gkKTei2WBxfTsLzczxWNTYYwkSeSpHRLG/ox3PbrUKMb+PN01bdc/b
         lwVL75pki4FQUES5rHxAWc2GjBUosktWjLCva2llFWLxHrfmPLKNQZLTR5UHIDVlvrAP
         HPZApxj5MINKB0H+gSpsQnMgT2RWHfDB3GZ5KpI6HtZwFPtNO1ibOvfCGKilxtkyiPoR
         lJkmF3MBJY0VyqtfR0EXFVZ7BBclvaCrg703o89FxzLi1I9e0416IRtoAKy4IuvYqOUv
         0pyAv/TzbGhRR3vXup/gsC6KrkYe44XXJkHRvCVpWdI2MvTxDEIdxGq+4mz+WPq5z1wj
         ZC/w==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YxilvrdQABjzDZWnzG41sUPUEoMjHCLA0h/420S1rvrRnOphXy/
	Rfs8IXgN2mWzFy+2c71wQ3I=
X-Google-Smtp-Source: AGHT+IFqJCDrKFVFu8jHpWQd2eG0fQrkv/D/S47eNqbao8BXhPzdtYQHOwu3tEfOakaKQ876dz9O+g==
X-Received: by 2002:a05:6e02:156d:b0:346:6d97:ffd1 with SMTP id k13-20020a056e02156d00b003466d97ffd1mr3213985ilu.18.1694796660801;
        Fri, 15 Sep 2023 09:51:00 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a92:bd06:0:b0:349:3346:c3e0 with SMTP id c6-20020a92bd06000000b003493346c3e0ls749423ile.1.-pod-prod-09-us;
 Fri, 15 Sep 2023 09:51:00 -0700 (PDT)
X-Received: by 2002:a05:6e02:1d8c:b0:34f:75cb:7f0 with SMTP id h12-20020a056e021d8c00b0034f75cb07f0mr3337318ila.12.1694796659986;
        Fri, 15 Sep 2023 09:50:59 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1694796659; cv=none;
        d=google.com; s=arc-20160816;
        b=TEy4kHdMUVjoBQiBrBawLZrL8546AeW3IlEgZkl2SrITuYFaHVOAwYa+liGOUzkQ7S
         m+QNnN8NQfBR3SZWLHzsycsS5hn9SaYncTEFYngZxVFDaXKuGcMG5jFoME8iO+e/3vnk
         jjr+xPsGC+MJKoU51v5eMp749Txi6dCZHTlLyOFEMds9MIxbsX9dPX6/s9Gk54c4CEw+
         QXrhf58XnqQeZrSpcPxsk2FeeaQ2x/BVTW8cgOqzp0iQoqzx/mtJrAG0PuCezUPPz5W3
         E9M6IURybuljimbdlERHOBGEYR7VWqhkk1oyFuB3pDKcwNbq7Sgyn6PiC9+wvZMenNsZ
         W9bA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=C9N4U7m1ENfkMXf6AuPL4MT6Lni4JryuzWdzOGtlKI8=;
        fh=K06HltD1s8cLQtWqVooCEx8EITvFUygkYMCHJkZOESY=;
        b=qffRVsXfxZEo3YHXc1XXpqgkIFaEoKoHesKCzhuiFs51Xo+1wK2X0sXOuf5/HIaexI
         S+oVqHu+bQZWMk1SWuDGG7hOE0Sc2BVA7uFu2Keyxt1gg3Nzd+uxkc3kHM1+zw1rZy5d
         LQt0RzcKxUhVjHZ2VSHq6H/6uXXumQfzhjrJYqboOv0qzV5KJ3mPBE+EiN4xeWZZThKb
         gkZ9yYUQ7GSqevsMtsO3NIE2qL7z/Wv4wBTA9jD2+fXj+4Oa4DkTNiAhI5/vLQqv6Xfe
         7BfT8zftPWfQd8YWjc9LVRsd+pLsiSHoCNymPWC+I2Ab+fWBwl8uypa4Ohp1Z26QT1Z1
         fzjg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=eqAegjm+;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::1029 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-pj1-x1029.google.com (mail-pj1-x1029.google.com. [2607:f8b0:4864:20::1029])
        by gmr-mx.google.com with ESMTPS id cl8-20020a0566383d0800b0042b05c84035si448252jab.7.2023.09.15.09.50.59
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 15 Sep 2023 09:50:59 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::1029 as permitted sender) client-ip=2607:f8b0:4864:20::1029;
Received: by mail-pj1-x1029.google.com with SMTP id 98e67ed59e1d1-274b9b3e0e1so1068a91.1
        for <kasan-dev@googlegroups.com>; Fri, 15 Sep 2023 09:50:59 -0700 (PDT)
X-Received: by 2002:a17:90a:f312:b0:273:e42b:34c1 with SMTP id
 ca18-20020a17090af31200b00273e42b34c1mr1902942pjb.42.1694796659560; Fri, 15
 Sep 2023 09:50:59 -0700 (PDT)
MIME-Version: 1.0
References: <CA+fCnZePgv=V65t4FtJvcyKvhM6yA3amTbPnwc5Ft5YdzpeeRg@mail.gmail.com>
 <20230915024559.32806-1-haibo.li@mediatek.com>
In-Reply-To: <20230915024559.32806-1-haibo.li@mediatek.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Fri, 15 Sep 2023 18:50:48 +0200
Message-ID: <CA+fCnZfuaovc4fk6Z+p1haLk7iemgtpF522sej3oWYARhBYYUQ@mail.gmail.com>
Subject: Re: [PATCH] kasan:fix access invalid shadow address when input is illegal
To: Haibo Li <haibo.li@mediatek.com>, jannh@google.com
Cc: akpm@linux-foundation.org, angelogioacchino.delregno@collabora.com, 
	dvyukov@google.com, glider@google.com, kasan-dev@googlegroups.com, 
	linux-arm-kernel@lists.infradead.org, linux-kernel@vger.kernel.org, 
	linux-mediatek@lists.infradead.org, linux-mm@kvack.org, mark.rutland@arm.com, 
	matthias.bgg@gmail.com, ryabinin.a.a@gmail.com, vincenzo.frascino@arm.com, 
	xiaoming.yu@mediatek.com
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=eqAegjm+;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::1029
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

On Fri, Sep 15, 2023 at 4:46=E2=80=AFAM 'Haibo Li' via kasan-dev
<kasan-dev@googlegroups.com> wrote:
>
> The patch checks each shadow address,so it introduces extra overhead.

Ack. Could still be fine, depends on the overhead.

But if the message printed by kasan_non_canonical_hook is good enough
for your use case, I would rather stick to that.

> Now kasan_non_canonical_hook only works for CONFIG_KASAN_INLINE.
>
> And CONFIG_KASAN_OUTLINE is set in my case.
>
> Is it possible to make kasan_non_canonical_hook works for both
> INLINE and OUTLINE by simply remove the "#ifdef CONFIG_KASAN_INLINE"?

Yes, it should just work if you remove the ifdefs in mm/kasan/report.c
and in include/linux/kasan.h.

Jann, do you have any objections to enabling kasan_non_canonical_hook
for the outline mode too?

> Since kasan_non_canonical_hook is only used after kernel fault,it
> is better if there is no limit.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CA%2BfCnZfuaovc4fk6Z%2Bp1haLk7iemgtpF522sej3oWYARhBYYUQ%40mail.gm=
ail.com.
