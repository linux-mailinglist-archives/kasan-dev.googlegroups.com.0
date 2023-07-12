Return-Path: <kasan-dev+bncBCCMH5WKTMGRBSPFXGSQMGQEEUS5URI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3d.google.com (mail-oo1-xc3d.google.com [IPv6:2607:f8b0:4864:20::c3d])
	by mail.lfdr.de (Postfix) with ESMTPS id BB8EA75031B
	for <lists+kasan-dev@lfdr.de>; Wed, 12 Jul 2023 11:30:50 +0200 (CEST)
Received: by mail-oo1-xc3d.google.com with SMTP id 006d021491bc7-55e16833517sf6873154eaf.1
        for <lists+kasan-dev@lfdr.de>; Wed, 12 Jul 2023 02:30:50 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1689154249; cv=pass;
        d=google.com; s=arc-20160816;
        b=gbqRAaDERDhYZt2aIDbTAw/t32N7FKsxsKgjHGgaLDHs5fcTe9Ih/0rG9v1CsPbeo8
         yp6iP0uJ2MJvMAj6KfdF9uj3crPCUMmC/dthFDtNvUFKvhYdAaJfierTSw4rstW47f++
         gVsGNv024O0aTI6V/dug6CZoR0ae+G5oCHolO7C4D2UMecama/ymsReFzFBNFrwTR0y5
         ea3xD7jJ+HhJ4I/OyBxenS9OMYFc1RTaGevzzqvRk75/1CtU8elB3s7nVIE2RQV3+YQH
         7lk1PqE+LgISJbObtg/5FEzwtC7GhCYLMt1xxESqooBs9CZHGmS15lysSpiSFzvKPnmG
         zWaw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=k1lig5a0Q0ucjAdjAx4TJ/zMymz0jPE9DItkptq595U=;
        fh=I3l6q8BZSEVVxw0ZZxCYQ0USDIQ5E58I2gGuaSqKBkM=;
        b=ZoKYFz5e1gcVK3CJwfUZoIS94AAbCopMpbXaezmfFrMVzFVA4RsFnv3v8ecCb131eJ
         wq+04QtnAr/0R9CG8mCIuH5ircTmzF25LapVr2Y9Yreekn/gQf1bnyweAlRjTYZ2UjCS
         +zJ3sfbY1zlXtBUNW5dQLlGb4LENwS7qamQOas3qza0nGL5vkCYnMm0siXDPVtjQL89y
         im2VxRFwhtnl/VKnIWoArCbYLo+Ylh3imvtqBeP92+kpMkda8wmvrwtWzL89ir5ZFoq+
         VGS/IFmVoD4uGO0NgpHfhS+EJVvwMefX9jjBnUeVA81nurALYzbUUQb802c7vDO+w23R
         zPiA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b=JiHaHowj;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::d2a as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1689154249; x=1691746249;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=k1lig5a0Q0ucjAdjAx4TJ/zMymz0jPE9DItkptq595U=;
        b=FDQlz80/BvRz+tSXgZist6whhIUSlV94NyXBM0XKwK9ObEog568+GyGv2cg7PU5Jlg
         c6DWBpuuBQdVxB8l3nyA4AeA/D/EI7eSqH9BZOzBxTpGatgJWoPbDDpPwQgjyZTiNsyq
         pAxT+ICir2imjFzqf2MZJQ4vY2e2j1qCunzZl3XIalcq1+3TKkaxGO5dE93LL4Y+qBS+
         fnaaIdIRycb3v8L867iOpgpTx5Ej+KeFmV94wsVg2NZEzusTL8e9hFUJ9WQ830vdSu/x
         xAP0+EyKPpoX2Ovvjx/5djBEHTNojmvur9bZk5s/v9ZThV43zfF/gPQ1C7X0ZRZnXeYE
         +CHA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1689154249; x=1691746249;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=k1lig5a0Q0ucjAdjAx4TJ/zMymz0jPE9DItkptq595U=;
        b=jAw/bF8ZFM9ZB3SKdvetXuYeDETTdzVX87EPAypDnsUWl3uoLgboxT5wUANjs7jEd1
         fDsCwgxHkaNML/kSwEy5HbIKkxujIcqm1ynpStoiq6FviG2HY2obCea2J/XqGoMumfJw
         U3h5sejSz3paptgmNYtKTZTzg1qqpgGieCdBjCTCe0YGGP702qpNWU+mCwCsPVan7l+1
         MybMYrhYJqm+lm43L8GXHzpxnU/o9gZAN6gr3Knl+rJC43RrpmMWnOX0ao7GMx06s/Et
         +8HDNrIH29kXTaP0+P1USx/3jYNdxyMp6RPk68RzIbyP7dJf8GFZpuBdHqqdS2RwEs8h
         NRJQ==
X-Gm-Message-State: ABy/qLZYk/M791MJUOZHIHtdLOqeEnyRTpfvEkTiNKo5E9Mn5mM792un
	U5gde+EHfHwxbQ78TfE175g=
X-Google-Smtp-Source: APBJJlHADqj+ms0h8tERTAK4LyrrOG2d3OaDRhVgdQWyguE6a8Vyw+Y3E6cvYCWktgIBx/dn2LApyg==
X-Received: by 2002:a05:6871:b14:b0:1b4:6d3b:3e15 with SMTP id fq20-20020a0568710b1400b001b46d3b3e15mr15115527oab.3.1689154249085;
        Wed, 12 Jul 2023 02:30:49 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:d626:b0:1b3:e129:dc1 with SMTP id
 a38-20020a056870d62600b001b3e1290dc1ls1763308oaq.0.-pod-prod-09-us; Wed, 12
 Jul 2023 02:30:48 -0700 (PDT)
X-Received: by 2002:a9d:7445:0:b0:6b9:a399:85b3 with SMTP id p5-20020a9d7445000000b006b9a39985b3mr515661otk.34.1689154248650;
        Wed, 12 Jul 2023 02:30:48 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1689154248; cv=none;
        d=google.com; s=arc-20160816;
        b=JB6SXHFyavwY3hNBdGB7BxW0Q5Kp4/t/ZBpd4NJZ4wUMBVhYMS6eM/d1Owjir+aGxd
         FCCmqQ8d9scBk3SPk0t6tEVVbZxezuoN8Fg7/7jpxFjwPRUI3afPhXLXlE8Y5bJVueBo
         7/odByy8g4WpjVqiqAZVf2xxzW0MK3o9gCblYwayEzXX0HnxPTABNsbtLxHgg5ni8Rt4
         rQ7j96WA4Kt+Py5DgyvtO3HqYpcxAf6GmijprSP9VmVdmtr+P4X0Bllr+//OFtfrpis6
         gjDsYbeRcpMNNEqx2T7Z/t2OPcShjKF4Ais4oTg8M+3N1HCP7VPOx89Jg6AbobvkTk0S
         dtig==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=AtYtKFoXSNaR0HimX7VOb+3+TUw1E5irFW1i/Ff7fdo=;
        fh=I8TlVEBf2o11jnannDJ3ln3x0DL8glxwIDqILfWRWdA=;
        b=Aqm/vaXGlI/nVg2rxB6fs0iwVUHOAl5O674gVkSxJex89aPzO3xhUfg/jMF/Nk+j/C
         vPWyaCfkdWdVCV7pNZHV7MQj3H/sWBIbJoN45p5ZrimzDgxPHOHw+Cm18nTGEbEUTsW8
         KjmjgLsHJopgRFTqsUWxV0DNoz7bAsOzPxI4lfEvDMVGr6S97vRmR/NAUzfDBplxD6C+
         O6KslnE5t8gEvjR0YTNJDitON/xgaKonX3Et+38W1URlcfSoIt1EBn8nF1WZn5uzpp6N
         2NHQkGbvz+wdfcUG7Jtj0proRLAXmzrUHxS8S7mMO2DknSC0J4cUKJlUj0EAjZVcAK4m
         uf1A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b=JiHaHowj;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::d2a as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-io1-xd2a.google.com (mail-io1-xd2a.google.com. [2607:f8b0:4864:20::d2a])
        by gmr-mx.google.com with ESMTPS id bk19-20020a056830369300b006a5f12c714bsi650856otb.0.2023.07.12.02.30.48
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 12 Jul 2023 02:30:48 -0700 (PDT)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::d2a as permitted sender) client-ip=2607:f8b0:4864:20::d2a;
Received: by mail-io1-xd2a.google.com with SMTP id ca18e2360f4ac-7835bad99fbso213434739f.1
        for <kasan-dev@googlegroups.com>; Wed, 12 Jul 2023 02:30:48 -0700 (PDT)
X-Received: by 2002:a5e:dd0c:0:b0:786:ea57:22e2 with SMTP id
 t12-20020a5edd0c000000b00786ea5722e2mr14334765iop.20.1689154248240; Wed, 12
 Jul 2023 02:30:48 -0700 (PDT)
MIME-Version: 1.0
References: <20230712081616.45177-1-zhangpeng.00@bytedance.com>
In-Reply-To: <20230712081616.45177-1-zhangpeng.00@bytedance.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 12 Jul 2023 11:30:11 +0200
Message-ID: <CAG_fn=Vj+rqkz0_3kvBoBVoxET10KV-zoD=YtJmCfsA8YEMemg@mail.gmail.com>
Subject: Re: [PATCH v2] mm: kfence: allocate kfence_metadata at runtime
To: Peng Zhang <zhangpeng.00@bytedance.com>
Cc: elver@google.com, dvyukov@google.com, akpm@linux-foundation.org, 
	kasan-dev@googlegroups.com, linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	muchun.song@linux.dev
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20221208 header.b=JiHaHowj;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::d2a as
 permitted sender) smtp.mailfrom=glider@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Alexander Potapenko <glider@google.com>
Reply-To: Alexander Potapenko <glider@google.com>
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

> Below is the numbers obtained in qemu (with default 256 objects).
> before: Memory: 8134692K/8388080K available (3668K bss)
> after: Memory: 8136740K/8388080K available (1620K bss)
> More than expected, it saves 2MB memory. It can be seen that the size
> of the .bss section has changed, possibly because it affects the linker.

The size of .bss should only change by ~288K. Perhaps it has crossed
the alignment boundary for .bss, but this effect cannot be guaranteed
and does not depend exclusively on this patch.
I suggest that you omit these lines from the patch description, as
they may confuse the readers.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAG_fn%3DVj%2Brqkz0_3kvBoBVoxET10KV-zoD%3DYtJmCfsA8YEMemg%40mail.gmail.com.
