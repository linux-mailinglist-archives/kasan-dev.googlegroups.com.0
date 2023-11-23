Return-Path: <kasan-dev+bncBDW2JDUY5AORBDXQ7WVAMGQEZBKPAXQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf38.google.com (mail-qv1-xf38.google.com [IPv6:2607:f8b0:4864:20::f38])
	by mail.lfdr.de (Postfix) with ESMTPS id 41BFE7F6384
	for <lists+kasan-dev@lfdr.de>; Thu, 23 Nov 2023 17:04:32 +0100 (CET)
Received: by mail-qv1-xf38.google.com with SMTP id 6a1803df08f44-670237ba89asf18239776d6.0
        for <lists+kasan-dev@lfdr.de>; Thu, 23 Nov 2023 08:04:32 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1700755471; cv=pass;
        d=google.com; s=arc-20160816;
        b=jNHsFR7QvfdURGswVcn2EfPlet5LAyX1hTYMYpCaxC5ky0aw/sNgAC/AI3zSNRCmim
         2waLNfWtqM1ykOlZkh6Ysnu5o8bmJPDJuYvG+xM0KH2rpEkYLlW6VxczQXBmVSqiXxco
         LUl1f2rG12bLqtfgDt+y+/aW3bWHF8EoVv2bxa1SbZOjMMsZ2mOHcdimWRI7qwUab/JI
         gxXBposMf39dHS/zJfmqAt4a+g/ysyWYuwR1Fl4JV47AFtbpGIZ+xYdXa975i9xMmam6
         bW83ia9MVkal6Ztf3E9YbNUsV2uWh96KeDL8/qdeeRU6axqkp4qwm1ju/I60431ZPGKb
         gUHA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=szqltMmHoUXbo3MU4PjKC8eg1QHXXh5Mt5weAB4viKM=;
        fh=3qba5YkzTL+bXHTu4hEoWcPGCZaYcQppgGBvzQQIBIU=;
        b=Wn+WJ4m7Vi5nRncRBnwkP91eCeNT7tjxke4MVS6uPn1GnV+Mwx89Te78gGhCE1st2E
         mQmko3DSHY8bRIuNJgnY7sETbMNMW85QwDdAziYDm8oY9s99Vp1gawQNo0f8dZfGTyU/
         KMci98KnftoL1Kfh8tsvsd0yrwj7dR5sO+0oEuM1pPxsz4pqCymv2GmSng976NDT82D9
         fP+YBACMsPyX3Aek3plfcqMUqe27wNXvvFv8/o+9kPpFyDemg5GfGK4TPIFtNH0cjbCw
         N2fVLu9UNRYmNSHt66jt8IZtY1VZm15Xft0jsYKJEiNAx0lO0fAOxvkUvnw44ycCl2Jv
         a89Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=cntte4WM;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::435 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1700755471; x=1701360271; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=szqltMmHoUXbo3MU4PjKC8eg1QHXXh5Mt5weAB4viKM=;
        b=Pia2cleKQ+gVqIjJI8X+GOrIcRb2kvnuiQWoe/vHRqMqx0akvpZr3YWScOXMwi5K3k
         Uki29wiVqKheGR4z/HkNnDPAnaWu7no0sDSXRXNve4zyXfvSHfSrGlGMBR/W3Vn8WP+t
         5aF4h1PyBqjJDSVIP73aLy2reW6NQao5PeMp50J+Lb2nqRWSU+eFAxiy8EfhtxzCkYNK
         EMnlOYoCZfqe+tsqmPimllcp+9H1RZR0VznHAHimhVObzFlJjaykZTb/5N6Ylk7DG2/b
         SW5wl71hO8wIEZoA1Khrk3pWM9K8fD5/pknh9LP0jtA7LcKR545MQJ4EBxns1VgCeMK+
         LOtg==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1700755471; x=1701360271; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=szqltMmHoUXbo3MU4PjKC8eg1QHXXh5Mt5weAB4viKM=;
        b=mIoZhOeVlVG9LnkgaOlMCkzsvEpL7VwecmJ+9Ga7djMnvlopXmJAbhg9XR3cMWZ5NH
         0V34a17R9l14bzbTeqxZacFoVtr2SvCX5kehetqWrfe+ozATzwjUMJh0QfhFqvQrZAfL
         etFuf11/R86HBObGSWa22IBBEStOU5DL09XcF+NDp+ensfpSkmZeCAdoW+AZ4VDiD+Ni
         uIR3KwIeqgN4Kxv9OSrROYOBuT9L2cH5SVjkZIlDN8V8GLtHA0mxef3RvhsrlI+pZP/k
         +H4FT2pz8N29eY/hSTg+1027BhK9xaoRqB7x9OxfuNT8ZV3FEtEzo1MUUv56SjTl34Ls
         ffBg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1700755471; x=1701360271;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=szqltMmHoUXbo3MU4PjKC8eg1QHXXh5Mt5weAB4viKM=;
        b=d6p1+wVIynJZg6L9VJdX6IgkSt9JVTivgQNWFP+nUAG1OqPnMV33YiCNhgQbABkc68
         Qqy09T1Zj39gvfn0Bvtnepoxnj6WAvoooBRutY+wNCDY8uCTeTrHDhgfUY/yJ8KE+ioQ
         2fbdGzXQzjX9yLrWcMT5/vxvAM+85SYYHFlFvRPxaytJkX5D3Pc+cAGxGuZLdrg1nQdW
         xOQofSq4fc4HiLjQjyLCPZ/8FMGa/WTIoJ1gotRv8RVhGRhuw1pryZLFi8dcv46tild5
         hSkDVzC/eb/N2rSHllJmzxxCT+5fRaLBsNgJisGH3sK0tOvPsdbKaIBRn6HDX2QnYp/6
         Dong==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YyBL6MbWa/03uTkAE5US3zMIWm8RwTGKFXDxzJZxV7hDwfo7N6k
	QMSsje+k3mMVfDalYJhE5hM=
X-Google-Smtp-Source: AGHT+IGfsgiJ7tdeA+XwExqe1WSKef+PrgVxItE3Vukl2PMgDOhqbM35lHJ0OvyOex5lDUyl3F2fIA==
X-Received: by 2002:ad4:48c7:0:b0:67a:973:56cb with SMTP id v7-20020ad448c7000000b0067a097356cbmr2583440qvx.27.1700755470901;
        Thu, 23 Nov 2023 08:04:30 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6214:221:b0:65d:b9b:f310 with SMTP id
 j1-20020a056214022100b0065d0b9bf310ls1417729qvt.1.-pod-prod-00-us; Thu, 23
 Nov 2023 08:04:30 -0800 (PST)
X-Received: by 2002:a05:6122:50e:b0:49d:7af5:1973 with SMTP id x14-20020a056122050e00b0049d7af51973mr3179958vko.3.1700755469856;
        Thu, 23 Nov 2023 08:04:29 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1700755469; cv=none;
        d=google.com; s=arc-20160816;
        b=uIT3aAl+eU71av3k3p0lc18CwxLNH5PRfRRpM61HHqqSpxflMVY04jKr9MrZexKVcx
         NQrZuCmLItBizuHLf7Cf/D2kxoUYofjF1P1DswO6M4IirbxJE1RnAgTx+w5hU0HPTbHo
         F6VgmXOmCHdq4RH3CG6Qg2uFK/h/fnYADv8MRhJBZeZV+WhCaVKcmWEfTIICKcL/M+H4
         nRAbvURfGQC5wEGJIEMq/Cry2OVWTu0aruvtX4/JFGu645Z8bs/L/ir9eN8SBnMyQuia
         aXlAzUbKMllp/NbBD5na55oiBtv/+pIcpL6wrAWH8N0WDqaK8FF8cr150i9vV9fW33uk
         u3Cg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=1nBMYi0DQuFagtnZx4pcIi3eC9Jxr33rON8i5DT6+5o=;
        fh=3qba5YkzTL+bXHTu4hEoWcPGCZaYcQppgGBvzQQIBIU=;
        b=1IVLcMer0qwTibMclHV1w46PSFSqRd92H8hyUTqXH9iXYeLcK4pBLsqgKlDxbWH2RQ
         zUzkJGaKrdQQHQH2Jmf/Jg6TVG7k7i1Me58Ch223U5LMGBbNKm1HpLX7/y9d+8CohjW2
         NpUv/CI2SC4MtQuSD/IE39pPpYhvZkWlS0lDXpFRwa1V1q3EIj9yIjaas+2+O2dhCsVJ
         IL4NebKfLXmtUhddMVDySbzJuc+IHaAhZjLVvU7daw1hXBFFmr6o+/NkbxuwrWXuEqUY
         ornHekxLYBgy2QIKz2w+tCg6V2IMIvfZlupOzS64Sh6CD7DfKaNOkXZKNOMthXMnfOhs
         EkEw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=cntte4WM;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::435 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-pf1-x435.google.com (mail-pf1-x435.google.com. [2607:f8b0:4864:20::435])
        by gmr-mx.google.com with ESMTPS id ec5-20020a056122368500b004937daab34esi180090vkb.4.2023.11.23.08.04.29
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 23 Nov 2023 08:04:29 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::435 as permitted sender) client-ip=2607:f8b0:4864:20::435;
Received: by mail-pf1-x435.google.com with SMTP id d2e1a72fcca58-6cbb71c3020so1501796b3a.1
        for <kasan-dev@googlegroups.com>; Thu, 23 Nov 2023 08:04:29 -0800 (PST)
X-Received: by 2002:a17:90b:3b51:b0:280:a002:be85 with SMTP id
 ot17-20020a17090b3b5100b00280a002be85mr4198623pjb.20.1700755468832; Thu, 23
 Nov 2023 08:04:28 -0800 (PST)
MIME-Version: 1.0
References: <VI1P193MB0752675D6E0A2D16CE656F8299BAA@VI1P193MB0752.EURP193.PROD.OUTLOOK.COM>
 <VI1P193MB0752282E559B37F12EB7982599B9A@VI1P193MB0752.EURP193.PROD.OUTLOOK.COM>
In-Reply-To: <VI1P193MB0752282E559B37F12EB7982599B9A@VI1P193MB0752.EURP193.PROD.OUTLOOK.COM>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Thu, 23 Nov 2023 17:04:17 +0100
Message-ID: <CA+fCnZdTo0giqBjukHYpwjGL97NnVtmenHkg1YBi1Su+DoZf4g@mail.gmail.com>
Subject: Re: [PATCH v3] kasan: Improve free meta storage in Generic KASAN
To: Juntong Deng <juntong.deng@outlook.com>
Cc: ryabinin.a.a@gmail.com, glider@google.com, dvyukov@google.com, 
	vincenzo.frascino@arm.com, akpm@linux-foundation.org, 
	kasan-dev@googlegroups.com, linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	linux-kernel-mentees@lists.linuxfoundation.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=cntte4WM;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::435
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

On Thu, Nov 23, 2023 at 11:43=E2=80=AFAM Juntong Deng <juntong.deng@outlook=
.com> wrote:
>
> Can someone help to apply the new version of the patch to linux-next?
> to replace the buggy version of the patch.

It should appear there naturally once Andrew picks it up into the mm
tree. It's the holiday time right now, so I would expect this will
happen in a few days.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CA%2BfCnZdTo0giqBjukHYpwjGL97NnVtmenHkg1YBi1Su%2BDoZf4g%40mail.gm=
ail.com.
