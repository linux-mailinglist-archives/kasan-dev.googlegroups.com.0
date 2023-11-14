Return-Path: <kasan-dev+bncBCF5XGNWYQBRBQ7TZOVAMGQEKTHUSCY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53e.google.com (mail-pg1-x53e.google.com [IPv6:2607:f8b0:4864:20::53e])
	by mail.lfdr.de (Postfix) with ESMTPS id 44FFD7EA9A5
	for <lists+kasan-dev@lfdr.de>; Tue, 14 Nov 2023 05:38:30 +0100 (CET)
Received: by mail-pg1-x53e.google.com with SMTP id 41be03b00d2f7-5b7fb057153sf6141793a12.1
        for <lists+kasan-dev@lfdr.de>; Mon, 13 Nov 2023 20:38:30 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1699936708; cv=pass;
        d=google.com; s=arc-20160816;
        b=b7y1M79Zs0Pu6a02yrh5vOh0H5UTmCknZt+DBkWsa0zbpyH6PHHbI93CYVQALYJujT
         UjLrZL8VvWDG631upq5ODKsUPhKi4+WjQHE4uqAOxnzRyrxZBQmWrF/cpKD91doualzw
         Aw8Cul98YueoW7lLvNsMfCYBRA+9DT+i/XnnLRWH2P/Cd/89bFqAnzR/XrM3MDdCN6bR
         MAPuVp9hPWMC6v6VxjQiyI9zz/aaFM9L76QxYEFN3T12nhyeAAqRIUVWTyCyygUnSG77
         kGZ4YDp7q4URDFdvHcuTrlNbkxAM2M4Mj47qE9fGGODcg1kNgWlCZjwDP54TbLFwZjya
         cGmA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=UMyodeiOuQxRQO3gVHgBU0UBLBMxHzCiKsgdkCVYiDM=;
        fh=1kL6YZIf4gCjZD/dUA6xgrhZxlE48Jm84GD32EC2Zms=;
        b=IjSa8Zn4YVvGv+f9sBv+hbaOmqGT2ra7LJpzK1MSQwNPJBuF3zTKdm59SNYpWv/PW0
         YgFTMCUTeewnpeuvqtv9DmJbZdCJdoluS7mVarbLZX4vs1Qj3Iqqj20LNrgYtgEzoQZr
         0Ftp9dESED6udDhUj+hodkHxKp12BrlLBRfVoDGk7kCjZGZ3o90G/xESQ58xkvfaNGja
         64hBsp5cI7nqt5dYxmORDcabLnaxqE6nWjbeq80gOds/2OjZX82QpHvn+A+GFYtyRIym
         DCoCUAK39pHxQyo4qqG4RM/crXgi3pDlH7LQEnatrUbYcF0C2GDKuUSfTN62TMXJpdHE
         YJxA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=KcOC1LJJ;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::331 as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1699936708; x=1700541508; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=UMyodeiOuQxRQO3gVHgBU0UBLBMxHzCiKsgdkCVYiDM=;
        b=Kl+QeHcRFcEhy01CfNA/radvN6rn4k/rAbfXZoTrjn0+4qfXYle4xUXh+uCjEzWT3x
         TmUckHyKD0uqcLsbjTCzAyJ8zPsJHXnCrroJGLp1iXwZKB23Nfq74/WrdcYS0xy0CcJU
         /6g9iWym87HBtZCAhijkS2LWthHTGjXEn0NCmtseM3hxDl6eiG+ejtvDuVokjMz7Dfmp
         dFp3l36wMngVdGOA9x0zNScznVJiMmpJexXhGk6pD/jZm1MKz2VIAvufI4QypVMZjJhx
         SXsgn7MMH50ieJ/xhoZ95jcW04VmzRbMWRFEK2z6lGJnqd71vPcJvCBBTVLXWz8hNi5Z
         35Lw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1699936708; x=1700541508;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=UMyodeiOuQxRQO3gVHgBU0UBLBMxHzCiKsgdkCVYiDM=;
        b=T6RMYpbO1vG3DpBpLdQsSzQj1j7ot3gxotEsIl/k9ycJZtRo2hX3rAJ+4h3EGOej9m
         /dedxbYHx4W3I8pVZVrnqwXu0dwIqhh2IC0cTGRpJM2Fz3Z7ZFb+69FiOC1YhUsNqUrz
         ZXRPwDa1a6/EEslzub0MXL//o2KA8fki3BCr9+IhXbDARbuLJ4+6+c6SLkhGFQxtMRvX
         AKNMV/IkvZVOME5LuclkUPQHYaOR76dOPdkEZfiM554XHXUJu0O7FPdvzWVqeXPM9HqO
         Rku56N9q2zxk1P+8Nk/pPwoGZD+xo0eTloV1kneg8BWM5wx36c6QOF4waTzT2+DoLgoP
         UmHA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YxjGdqhlekMxOfMKgqMYHPcNk4zC4H4FrUinoku1iLPQW6sDIEf
	KD3cP8ZAptRr1kpiKFuNEFw=
X-Google-Smtp-Source: AGHT+IFYG/B2EtBOZUXm28yXLAXqYgSQK+oPEdpMbzjJPeDQQG1iqR5PSrvkuFbFrz7skm09+ByW5A==
X-Received: by 2002:a05:6a20:914d:b0:15c:b7ba:6a4d with SMTP id x13-20020a056a20914d00b0015cb7ba6a4dmr11204528pzc.50.1699936708056;
        Mon, 13 Nov 2023 20:38:28 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:ce18:b0:268:14f6:5312 with SMTP id
 f24-20020a17090ace1800b0026814f65312ls3377916pju.2.-pod-prod-08-us; Mon, 13
 Nov 2023 20:38:26 -0800 (PST)
X-Received: by 2002:a05:6a20:7343:b0:184:3233:679c with SMTP id v3-20020a056a20734300b001843233679cmr9878322pzc.12.1699936706699;
        Mon, 13 Nov 2023 20:38:26 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1699936706; cv=none;
        d=google.com; s=arc-20160816;
        b=hkcXYVVujSvh1vkm0Qmet+1tZUQgGPEeIJfPaWcUeUz/m+uHeRsjN4X7R24M5yrZp8
         zlzUPH6JFJVbfgJPFqY/VXvfPAElKyZAe4k0ha02q01AJlW3UEqDxPTfjRrHX2cLSix5
         6NubxhZko6VGx75sH8csxO132JzF/qeDLki2KFeYzLTKjv3+yTgQHDV3LNRcOsTIH7l/
         jN4sLeBn08wX9GdwuNOfyS5c17Q/J1vXnm/bnvVEV+TZVWuLQAylu1bs4ZnCUEB6/W6U
         NvWs2g/kL1gHYfbxDJpDkNk7oYPIA6U2dGYJ8hc1ncz8VNoy8WQY1zTDmCm+JCFmZcCq
         azew==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=cKLnTTpcsA4GTSpHutPlS9fMo+BLZ8ixEQsC9MUWwLk=;
        fh=1kL6YZIf4gCjZD/dUA6xgrhZxlE48Jm84GD32EC2Zms=;
        b=CKYLZFiy/W2tf4hLJ4MOpiR1OIa6Z79sLZ7ygka5TYUxdM344bcDRZfAWovsXJ7uHC
         qiqE2A1AV/B1WEz0E7ZUCZIeAl6u1jnYfIZj6K1zqrSwCZGIrYaUvusTPeaKyTzcyAh7
         0nNdYKpxqb9rDsAcVl3wRJAEaEKEuDMdZMAAhLZDLOISRbLiAktZRtUH0qm6AEOzyIiK
         DcpdcL2SS853GzUNO0mAXp5EdBYbdFZ1xBjfEQexBbbV6qunrgPvDfMPcgJdXNiblSoo
         gAwdswR2EiUQ7LYjaPjmjI1U/NiNDw1yWmYEHJXvhSwUaKIkT8BEAU+Q3YsIf736zi4n
         t6gg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=KcOC1LJJ;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::331 as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
Received: from mail-ot1-x331.google.com (mail-ot1-x331.google.com. [2607:f8b0:4864:20::331])
        by gmr-mx.google.com with ESMTPS id sh11-20020a17090b524b00b002814171f9b6si855650pjb.0.2023.11.13.20.38.26
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 13 Nov 2023 20:38:26 -0800 (PST)
Received-SPF: pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::331 as permitted sender) client-ip=2607:f8b0:4864:20::331;
Received: by mail-ot1-x331.google.com with SMTP id 46e09a7af769-6ce2ea3a944so3277268a34.1
        for <kasan-dev@googlegroups.com>; Mon, 13 Nov 2023 20:38:26 -0800 (PST)
X-Received: by 2002:a05:6358:914:b0:168:eded:d6c9 with SMTP id r20-20020a056358091400b00168ededd6c9mr1639355rwi.29.1699936705986;
        Mon, 13 Nov 2023 20:38:25 -0800 (PST)
Received: from www.outflux.net (198-0-35-241-static.hfc.comcastbusiness.net. [198.0.35.241])
        by smtp.gmail.com with ESMTPSA id q14-20020a63e20e000000b0056946623d7esm4832935pgh.55.2023.11.13.20.38.25
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 13 Nov 2023 20:38:25 -0800 (PST)
Date: Mon, 13 Nov 2023 20:38:24 -0800
From: Kees Cook <keescook@chromium.org>
To: Vlastimil Babka <vbabka@suse.cz>
Cc: David Rientjes <rientjes@google.com>, Christoph Lameter <cl@linux.com>,
	Pekka Enberg <penberg@kernel.org>,
	Joonsoo Kim <iamjoonsoo.kim@lge.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Hyeonggon Yoo <42.hyeyoo@gmail.com>,
	Roman Gushchin <roman.gushchin@linux.dev>, linux-mm@kvack.org,
	linux-kernel@vger.kernel.org, patches@lists.linux.dev,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Marco Elver <elver@google.com>,
	Johannes Weiner <hannes@cmpxchg.org>,
	Michal Hocko <mhocko@kernel.org>,
	Shakeel Butt <shakeelb@google.com>,
	Muchun Song <muchun.song@linux.dev>, kasan-dev@googlegroups.com,
	cgroups@vger.kernel.org
Subject: Re: [PATCH 10/20] mm/slab: move the rest of slub_def.h to mm/slab.h
Message-ID: <202311132037.F4FA0B2@keescook>
References: <20231113191340.17482-22-vbabka@suse.cz>
 <20231113191340.17482-32-vbabka@suse.cz>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20231113191340.17482-32-vbabka@suse.cz>
X-Original-Sender: keescook@chromium.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@chromium.org header.s=google header.b=KcOC1LJJ;       spf=pass
 (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::331
 as permitted sender) smtp.mailfrom=keescook@chromium.org;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=chromium.org
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

On Mon, Nov 13, 2023 at 08:13:51PM +0100, Vlastimil Babka wrote:
> mm/slab.h is the only place to include include/linux/slub_def.h which
> has allowed switching between SLAB and SLUB. Now we can simply move the
> contents over and remove slub_def.h.
> 
> Signed-off-by: Vlastimil Babka <vbabka@suse.cz>

Now is the chance to do any whitespace updates! I saw a few #defines
that looked like they could be re-tab-aligned, but it's not a big deal. :P

Reviewed-by: Kees Cook <keescook@chromium.org>

-- 
Kees Cook

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/202311132037.F4FA0B2%40keescook.
