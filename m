Return-Path: <kasan-dev+bncBDW2JDUY5AORBQOL3CTQMGQENJFPSBI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc38.google.com (mail-oo1-xc38.google.com [IPv6:2607:f8b0:4864:20::c38])
	by mail.lfdr.de (Postfix) with ESMTPS id 94346791D55
	for <lists+kasan-dev@lfdr.de>; Mon,  4 Sep 2023 20:45:22 +0200 (CEST)
Received: by mail-oo1-xc38.google.com with SMTP id 006d021491bc7-57128334fb2sf1202024eaf.3
        for <lists+kasan-dev@lfdr.de>; Mon, 04 Sep 2023 11:45:22 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1693853121; cv=pass;
        d=google.com; s=arc-20160816;
        b=tHkF0XSS38Eg0avcq+pn9TNkU2XtzSgiL/uFCtJxcqW7vzYdpiOMeUvLuUtilszUym
         SwgM6PRy/5yfohX8CIhiW6qo6SQXuTVZ6IhVTa9bfC4Zo8K+UbY/qH4Rx7i4iUQ9Dt4W
         yzAbumsiUoQvUEuwyoD3iOZ2IpwZTBNK+zy6/xzb75osNzasi++uSXJLRaluzpdUSaJo
         3xsRBUhwbVKse3BZpETn+Rvir1C3qol74THA7pM7U5OiKh7QbbtCHqYlB+B+zsvxvLdk
         SHAQgoQowb1uj8vCifb6QB8ykrLBfpdh/qWAOYy5NtiL0Vz8N1uoKgg0ttoixN54WyTc
         ZBXA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=AIXFyz/tSQiV+ZjSHn7xbNuLTUiNxnctZGjCmA+5mBw=;
        fh=31kqTpjmyf2nvpbJpXjTMp1IIQPLgMYNyzBwL/crNJA=;
        b=0MSTid3Waq/KxsTM2xDEka3nUDDj/Tf8JunFJcjoOMfGWmPEwh+S2HwluoWXU6s5+z
         KyZiR4/Cdx8PtoemsyJThO2xEKo0i3OcOnk5/PpxVCCjcFJpAkMdSPSCae2noDgudv8H
         bpsTNPvrzRhLLFinzO1w6/GE1GmuO0DU43yVemu2OvJyTBMwbLN0+ZxryEfnU0eFsvhg
         TH1FHcx1tO2NQv8nO0ihGNdv70LxOXbT2QpiiIqmuFU8mr+BSSsV1uWhP/KIGBJGk68r
         waW8SJREDsq9e2vrsdLiW9mP3dhAl5QYtQdQT8AtZuWavJ4U/68EbNbPIILr+eQYQnWU
         Q7bg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20221208 header.b=oUi0ZJ2D;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::634 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1693853121; x=1694457921; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=AIXFyz/tSQiV+ZjSHn7xbNuLTUiNxnctZGjCmA+5mBw=;
        b=NTDBmEDWdUKUfn7VUDK8aTKIslxSXg1ypqTR+7GdDnafb9F3LGDQQqz5TOoB2jwYLT
         LdqADcGdYmZJzjGtj7eIAY+Fi7/6nv77V0L/G0ZqzqUJVtg9u8L0QyGigHyYtmNkR/AD
         rdabhuDWNECnTNso7WrDHeMTFxv5Ch/wwsG5UJikNVP/xjEh22qdMCzDc+95/qYieDlN
         vsVmRklF0mD7imaJRYz3bhzLOGrKtp4OfFPGMZ14DeLH/OQJtSdfPUSw5V5vWGFQzQAh
         0Wu5L6ykOugSmUGuKDOOO3wRDP1VNv1s8rMOYbl4ad7fgGnE2iVo1CFfwo1aZzDLrFsY
         bGuw==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20221208; t=1693853121; x=1694457921; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=AIXFyz/tSQiV+ZjSHn7xbNuLTUiNxnctZGjCmA+5mBw=;
        b=oqZwCm+qiICTxrvIv/k5+mzz3tb9HjcjBn93fUMNqCL02ZhxOZwJpY4IKKQOGSMYmM
         x8LfiXzYtDl3HiDZPMIFqNk6yNywbzB0RpYeKKrEb55+tel2eOvdwg+eB8M7Z6CFa4Hf
         CC2ixW16+khtd6t/9KKbo70t6SAIp50SBpCo+oFO2xA8pREZULCgrtZH53Dr/jfzPtfN
         LKZsp2ElKeaKRJ4GBU+E5gM1/iG+INHLXlvi3WU7PsIL01ze2fU/7fKCdBvi0jTBg7l1
         AE6SkuPmJyvjgXEE86t2mF5UE60WciQ8bCzVxbLRaJ7Kl8BaZLZbJ+uJ1Y+8lAIKL/p4
         Uo+w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1693853121; x=1694457921;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=AIXFyz/tSQiV+ZjSHn7xbNuLTUiNxnctZGjCmA+5mBw=;
        b=ABMkoISKgDGsog673u4D3++ZEdJzLkMO/vZUQs4nRZvM31ovxJfNXyDu01XRxqDOVJ
         efU+DDiX7cK+GpUd14gM2MdgJqX7gi8OourNw/uOoE9UYG06iUmy2dpl1WTU5Q8ol34O
         yh71xbB7YRMXPk7MDSaZB09BIgCxDEkWdqLXAossbgzet6v35HNTEi9s5BAG+Uz/Vmm0
         oAXSBGI1TiGJzETLldRC5r1fi9T9Gbjn50RGoAhhmpXK61Gmh0m7qnv8eMPtnZz+1d5o
         wpZ8SGxkTgYvXAAwFFjkj9TKI6TTn9OkwGmz5spahN+d6q6nYbuve+DbUa+z8OpXBMZT
         WrdQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YwMg+vX+qGNOmmt0GrInF6xaPpnof0JG3W9QJfxeGRn/hXbNFnj
	pq29kokXvp/ZYjApk3/guNE=
X-Google-Smtp-Source: AGHT+IElxSF3Pncvj5iGTFjJqroPgpxW8eaqYVl3wKFjUHGi9zJdeCed8uZ22K36QtF+CgPB2uSu3g==
X-Received: by 2002:a4a:301e:0:b0:571:23ce:a4af with SMTP id q30-20020a4a301e000000b0057123cea4afmr7862899oof.3.1693853121254;
        Mon, 04 Sep 2023 11:45:21 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a4a:44c7:0:b0:573:39c3:49df with SMTP id o190-20020a4a44c7000000b0057339c349dfls270773ooa.0.-pod-prod-06-us;
 Mon, 04 Sep 2023 11:45:20 -0700 (PDT)
X-Received: by 2002:a05:6808:10d5:b0:3a7:543d:9102 with SMTP id s21-20020a05680810d500b003a7543d9102mr11734897ois.39.1693853120667;
        Mon, 04 Sep 2023 11:45:20 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1693853120; cv=none;
        d=google.com; s=arc-20160816;
        b=F6jyKS5RqtjO4WC64SWb23Qs4avMqfy5TJ9vQpteDzqF1Vx6fZtoZ7E8oEjLgR/9+Y
         NViH/8soYowavwm2gN15UOOxv+ZGKaSpdNVRIA/BWzXLeJt69r0XUlKQK/h+anwUzr3s
         4kim1v5wBKiiYJFuuJVLGHCPC4kWVI1O91NVx4ITRKoJdFTtF0Uq/6dxL7iM1oT5H7FA
         LANIaXAV+E6hRk8lSGe2rkX0K+PcpEQBlnoshVUY7P1rPUKaKiiQ5/19nZfTpDn7TctB
         Qjpu3HmTLkW5n4sd8ZtI4fo6jQOv+kk9klK6nw3KlTAxvHcmMPhAfwyhRSE3AmPsck2E
         e/sg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=tIC0vvBtQknXQrQ2iQzcpIL5nVgglpSsEX1r8/R4Dm4=;
        fh=31kqTpjmyf2nvpbJpXjTMp1IIQPLgMYNyzBwL/crNJA=;
        b=ibvIK4D+WEVOSv5lB37vkFP1D8hTDBK8q/SE6HqThAMB+HXgcmmBBk1JJORdDQWoNl
         GUZ7unPItZkyJBGXWCNkmj8xxoKqA91XNtjniphk0OgayjzPZQ9y6Y26EpOBrhLcl626
         T8F7VmjGm3M9hBKFO0jjrCOWL5SUa/ldExWLr2GJi7ohpNof6yoJQGJYWksjuC2wstGF
         dZ0W/kDX1WxwyGgYWWu5FXzsZuAjxv1ZCf5szhdCPqpx6K6h5R3xANcUks9UfoatmHAQ
         vX9iV9jmJfKDUv/1dMA5CPkkIbpOeC5aufSnhgLWhGuvbpzY9Dg6jI14cqyjidQKt89i
         plTw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20221208 header.b=oUi0ZJ2D;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::634 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-pl1-x634.google.com (mail-pl1-x634.google.com. [2607:f8b0:4864:20::634])
        by gmr-mx.google.com with ESMTPS id f17-20020a05680814d100b003a7cc78b4c8si1700518oiw.2.2023.09.04.11.45.20
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 04 Sep 2023 11:45:20 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::634 as permitted sender) client-ip=2607:f8b0:4864:20::634;
Received: by mail-pl1-x634.google.com with SMTP id d9443c01a7336-1c1ff5b741cso13171145ad.2
        for <kasan-dev@googlegroups.com>; Mon, 04 Sep 2023 11:45:20 -0700 (PDT)
X-Received: by 2002:a17:90a:4b08:b0:26f:e9fd:8287 with SMTP id
 g8-20020a17090a4b0800b0026fe9fd8287mr9859030pjh.20.1693853120048; Mon, 04 Sep
 2023 11:45:20 -0700 (PDT)
MIME-Version: 1.0
References: <cover.1693328501.git.andreyknvl@google.com> <3948766e-5ebd-5e13-3c0d-f5e30c3ed724@suse.cz>
In-Reply-To: <3948766e-5ebd-5e13-3c0d-f5e30c3ed724@suse.cz>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Mon, 4 Sep 2023 20:45:09 +0200
Message-ID: <CA+fCnZdRkJTG0Z1t00YGuzH4AFAicGUVyxFc63djewRz0vj=pQ@mail.gmail.com>
Subject: Re: [PATCH 00/15] stackdepot: allow evicting stack traces
To: Vlastimil Babka <vbabka@suse.cz>
Cc: andrey.konovalov@linux.dev, Marco Elver <elver@google.com>, 
	Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, kasan-dev@googlegroups.com, 
	Evgenii Stepanov <eugenis@google.com>, Andrew Morton <akpm@linux-foundation.org>, linux-mm@kvack.org, 
	linux-kernel@vger.kernel.org, Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20221208 header.b=oUi0ZJ2D;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::634
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

On Wed, Aug 30, 2023 at 9:46=E2=80=AFAM Vlastimil Babka <vbabka@suse.cz> wr=
ote:
>
> I wonder if there's also another thing to consider for the future:
>
> 3. With the number of stackdepot users increasing, each having their
> distinct set of stacks from others, would it make sense to create separat=
e
> "storage instance" for each user instead of putting everything in a singl=
e
> shared one?

This shouldn't be hard to implement. However, do you see any
particular use cases for this?

One thing that comes to mind is that the users will then be able to
create/destroy stack depot instances when required. But I don't know
if any of the users need this: so far they all seem to require stack
depot throughout the whole lifetime of the system.

> In any case, evicting support is a good development, thanks!

Thank you!

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CA%2BfCnZdRkJTG0Z1t00YGuzH4AFAicGUVyxFc63djewRz0vj%3DpQ%40mail.gm=
ail.com.
