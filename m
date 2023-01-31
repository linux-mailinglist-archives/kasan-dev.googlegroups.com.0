Return-Path: <kasan-dev+bncBCCMH5WKTMGRBDG24OPAMGQE4EDQHPI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yw1-x1137.google.com (mail-yw1-x1137.google.com [IPv6:2607:f8b0:4864:20::1137])
	by mail.lfdr.de (Postfix) with ESMTPS id 41501682A77
	for <lists+kasan-dev@lfdr.de>; Tue, 31 Jan 2023 11:27:26 +0100 (CET)
Received: by mail-yw1-x1137.google.com with SMTP id 00721157ae682-5065604854esf163183827b3.16
        for <lists+kasan-dev@lfdr.de>; Tue, 31 Jan 2023 02:27:26 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1675160845; cv=pass;
        d=google.com; s=arc-20160816;
        b=f4ZW40Qz47gESVTFJJQh6YZ87t+s0+tIYZtcFv+qMSgOdN2b7Rbj/L6fJZqSPXILat
         o3W1alRskoCWJ4CGvaH5sD3RYSttIQnAoZiviUsDp4fHdgdU0iytlDr7yiMko4ZlIhvA
         KVtFgufpvoZxcB57LtJrYYieUBYKzrhUUWsXjR9zpCsdgQgge7rlQso+GI2z5CjZl0KR
         jEwKjyGa0BT9KsdZIViVYbvWL+s1PxkeYQ85MTYBf2aLia1MHLBYWHKgnrmHonrB44mi
         5EjkvwCZIuTv4MpS3bNu2dx+HD0iAq3Fu8mPYVfoe6LCc3y/5McZFeA233QsIU3iA7p4
         oLvw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=l2VdWKaK0xvA3AEo1Oa/mse5Vpjn7xtHv8xd/IpxP/I=;
        b=m5kNbcuPSIAJdXMaSQXO6ImpS0mVdEEBBMumWNvT5LKPZLRETr8HBuB1LxfVtDsnH+
         NW7m1BYsdiJ8YpZmc+PLtYtZQIK6X1GFo7kJA3+Yr43f73ZbUneOTy4mXxS6UaLAl0Q9
         RoRl/PN7MCplAYRC6p4GzQDEcTqBgsTTAs2PsIbcGKGluOi2sMc8TzXtiLu/Qx6/LWkt
         AowUAhw6TiVLXkreMu7YtKLlKpudMGOxtjs8iryrmOtCdHqC7UFPRf6Oncw6B1tFmiht
         mi0Ddd6IL7EbqOlXL0/xZAnFgbMsWqkm9/toLMTfskMxks92fmg44j05Ep045gfs+Kyj
         wMlQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b="d0QrZt2/";
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::e2a as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=l2VdWKaK0xvA3AEo1Oa/mse5Vpjn7xtHv8xd/IpxP/I=;
        b=LJZBgcXLeXQ60DlOseHEVMGW9Pt+1JABtp8I5bpdvaVEGC0uyVH1892Q17PbosXliQ
         sDHlihs9ODCmXKhLY8/MtkHAmuaAYss9lLGxHuDI98HGq+VN9IftHKYEZId+Jkpn9d7f
         AiD2DHPqsoyNw9CXYpHoWf8+5ZbONwNzBn205z1xNJP4HyFbaU3xBrjVKRpxt9f+wrK8
         /oiEpFMaJhx8Vn0nMM4xAvVgd3wbvTY6Pz6lOxK97r80eAprRRhbl1vWfz9xeSeS5f4S
         hxyPDkuxBncilMZH69wAbTqe2Ni72s4v/k/XAQ7UKovRbqZ/hDQnK3eY95S4AqD5r/i2
         POkw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=l2VdWKaK0xvA3AEo1Oa/mse5Vpjn7xtHv8xd/IpxP/I=;
        b=HYJfm4LKrM8yVJ6/kzD/DWcZy5mOBbN07Cn4ZxMSG2supgJhuSKkLnK+Rl5QBGjyql
         lNxoktLgT7pgl4+Os5hWYXWBc4XBahdfqxUHRvjH3un9WbE0pRRJhOh5byZz5LQYI14S
         zpEpePsCYEfzDJTan/4AhKUo4OafMLA5WsT3rJHlr90dUcbX5eRwgomHy1gt/UYmnwc+
         k9AwthUtPicDPtnxSGJcCzMwcJ6YFv/eh2oF/IavSSNQ5Zhf0pDN2ihhCP+pioRiQ97M
         BxI5mP3GKt562YkiLnrWD4A7pwNf1PxLHbLgq1PNVIbmqU7ZXCEDtUmhRutbv7P9K9lc
         HyNg==
X-Gm-Message-State: AO0yUKWRFceMaKiPB6u1pm02+iK/JAUStBEuS0l5GLNPpoNaxktdHH9c
	+IeGwDI5irjxV33T6HgCdJo=
X-Google-Smtp-Source: AK7set/Xwkg+KhsREPTq2FfVDxtZfiml9LVSlSkHE7rtvBjTHOE74gr4Y6O68ZGQdWVYCRfa6ueMUw==
X-Received: by 2002:a25:6808:0:b0:80b:75a3:fc16 with SMTP id d8-20020a256808000000b0080b75a3fc16mr2910828ybc.503.1675160845085;
        Tue, 31 Jan 2023 02:27:25 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a81:7d44:0:b0:506:83f5:16c0 with SMTP id y65-20020a817d44000000b0050683f516c0ls9821243ywc.11.-pod-prod-gmail;
 Tue, 31 Jan 2023 02:27:24 -0800 (PST)
X-Received: by 2002:a81:4f0b:0:b0:518:f966:ef85 with SMTP id d11-20020a814f0b000000b00518f966ef85mr3676927ywb.52.1675160844416;
        Tue, 31 Jan 2023 02:27:24 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1675160844; cv=none;
        d=google.com; s=arc-20160816;
        b=wJvMJf93K/NugyLZ3KByhHeSrgCKVaBIpY4G5HDVx1cGLWjSii212oUo7gJIjstJq4
         rq67l/B5ki91EHi5FNHAJmTl3Z2sBpbnNjS9oQi/Av9D7DikquU7G2fmnFZhEcubMFeR
         V7oz33h/aZQldahxkm5YlaCxiWlLxZGGcJdIKYTpoXrzW/1lNRu90A6yTIkUY5844z7z
         kCMjSU4IHtyjd66qRddDNkWpoethP3ynt6ds238B9fR8ew11GlPyNAlOqWburj3DGzGA
         eAh7zcJytSLwZrcclFpXw7JkNsZW/BQwEIvGQtZzQkl1Iao4vHN0Cg1Sy/FLqvGRvBfl
         MA7w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=7vPWeuf5HEeoiMZZem+4HAgZK7oUQUzCNRu6zAcOzxQ=;
        b=pE6RyAGiVEPxroiDjmUDNrJDnxdGUgzjDbmbpw6DOYH3itE5xxUqNNDTcRp7zL8Tz5
         flyp8MA21lJazkJplHyJcaFTR3SmdIs067IW3QFO2WaVwfo8gpa8N8PlYgd9NmYox+rt
         7n5595BsfHe4UH6hNb59+OFxiuZ8Qb0YTQNiEHmmPSeTQ4F4+Wt/HJv5peZ0NtirBG+7
         e1ht/cH4U9/yoK0ppFcnVzKuQ7VUVYCtwNDVrlky8o9NbYP7tM6lUKZjrkHdsWkbFhv+
         HJN2yg7ixuqgDBfwn3vWF1+FLRue0lSFaUTjD13d4VrONEercbFPIAxUhe+UXTxifjn0
         icRg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b="d0QrZt2/";
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::e2a as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-vs1-xe2a.google.com (mail-vs1-xe2a.google.com. [2607:f8b0:4864:20::e2a])
        by gmr-mx.google.com with ESMTPS id g137-20020a81528f000000b004e0c0549c53si3010932ywb.2.2023.01.31.02.27.24
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 31 Jan 2023 02:27:24 -0800 (PST)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::e2a as permitted sender) client-ip=2607:f8b0:4864:20::e2a;
Received: by mail-vs1-xe2a.google.com with SMTP id a24so13455087vsl.2
        for <kasan-dev@googlegroups.com>; Tue, 31 Jan 2023 02:27:24 -0800 (PST)
X-Received: by 2002:a05:6102:3237:b0:3f4:eee1:d8c4 with SMTP id
 x23-20020a056102323700b003f4eee1d8c4mr1110810vsf.19.1675160844015; Tue, 31
 Jan 2023 02:27:24 -0800 (PST)
MIME-Version: 1.0
References: <cover.1675111415.git.andreyknvl@google.com> <cb34925852c81be2ec6aac75766292e4e590523e.1675111415.git.andreyknvl@google.com>
In-Reply-To: <cb34925852c81be2ec6aac75766292e4e590523e.1675111415.git.andreyknvl@google.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 31 Jan 2023 11:26:48 +0100
Message-ID: <CAG_fn=VPVrp8BW=QpN63o40NSuJCd0P5aJee4gBod7JUgoQ4ig@mail.gmail.com>
Subject: Re: [PATCH 04/18] lib/stackdepot, mm: rename stack_depot_want_early_init
To: andrey.konovalov@linux.dev
Cc: Marco Elver <elver@google.com>, Andrey Konovalov <andreyknvl@gmail.com>, 
	Vlastimil Babka <vbabka@suse.cz>, kasan-dev@googlegroups.com, 
	Evgenii Stepanov <eugenis@google.com>, Andrew Morton <akpm@linux-foundation.org>, linux-mm@kvack.org, 
	linux-kernel@vger.kernel.org, Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b="d0QrZt2/";       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::e2a as
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

On Mon, Jan 30, 2023 at 9:49 PM <andrey.konovalov@linux.dev> wrote:
>
> From: Andrey Konovalov <andreyknvl@google.com>
>
> Rename stack_depot_want_early_init to stack_depot_request_early_init.
>
> The old name is confusing, as it hints at returning some kind of intention
> of stack depot. The new name reflects that this function requests an action
> from stack depot instead.
>
> No functional changes.
>
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
Reviewed-by: Alexander Potapenko <glider@google.com>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAG_fn%3DVPVrp8BW%3DQpN63o40NSuJCd0P5aJee4gBod7JUgoQ4ig%40mail.gmail.com.
