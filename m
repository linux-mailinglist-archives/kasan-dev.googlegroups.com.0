Return-Path: <kasan-dev+bncBCJ455VFUALBBX7G77EQMGQEW736WKY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103d.google.com (mail-pj1-x103d.google.com [IPv6:2607:f8b0:4864:20::103d])
	by mail.lfdr.de (Postfix) with ESMTPS id 85FA9CBD85A
	for <lists+kasan-dev@lfdr.de>; Mon, 15 Dec 2025 12:39:13 +0100 (CET)
Received: by mail-pj1-x103d.google.com with SMTP id 98e67ed59e1d1-34c93f0849dsf1015647a91.1
        for <lists+kasan-dev@lfdr.de>; Mon, 15 Dec 2025 03:39:13 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1765798752; cv=pass;
        d=google.com; s=arc-20240605;
        b=Y30D701gEmnOgT6QkeXA2jlN2WbpmL5UCBb+UrtDnyywjJNjywHh+jNdxcZNcAQl+b
         oMI2a5+sd24ZLYiRCEURHNpaipqRl3qsSZXj/w6mvMglrauEp4bazbAR6ZZiXKvaXe4K
         NnM7qBh0AR4uPECJqfjL/S7M7PG/94Wfez1klslckuAu3y+rh1+lqCIBeRWIC3OCoJLG
         CQdjEZn9HygxiWpviCrx8FD1LEP3Db8+s76ZPmIImqnRegi4cRtj9xxcOKyA59mkXW1m
         ed/FHmscu5GYuHmnkkvQAQoJQg3jqny2BGhcMYIBPQJeH1EqPVWEsaPeOIAqKAQVrRjy
         MFJA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature
         :dkim-signature;
        bh=c+nTznDhynRMciuweJtM/4a/S4R8C2W9VEK7zOuSW/I=;
        fh=15pY8V757BI3/iyMX7191CrfIPI+EheYPP6dshA07ag=;
        b=XBLxi0KKAHJy6vOjlbxChWrMnKd5iMNOMypuCvlReUcPXmBrLdZWqTGlzmLDSuzISj
         XgoZ70huc2CgiDP3Qk1Gzkv2xw0vdb7MhKmSlAT0Q6GETUXIHk1CkcIuzSs7zQcikrff
         t4udmyVBFT+Gj6wdE6OwuNsmQ++hE6w8ZBL2/9herzzgi4vWlzybyKmHJvCjdn81Ekm8
         Ied90R9ZybHj+6F9RhAz91Dma5L0Gy7DBMlbX6LTKeZvUzgq45F6qmBdZq78Cc8CSuN7
         UPEUdYdErjkisVs0yfPx54nC57haUSLOXobiCKDoBDdOhnhswKq7hMMQH0V24Z4PyAJ9
         BJJQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=U8mjiJIV;
       spf=pass (google.com: domain of bagasdotme@gmail.com designates 2607:f8b0:4864:20::42b as permitted sender) smtp.mailfrom=bagasdotme@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1765798752; x=1766403552; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=c+nTznDhynRMciuweJtM/4a/S4R8C2W9VEK7zOuSW/I=;
        b=H07WL2BQcshYy09rOt+bY/tCyRUTdXziOkd2mca+9IW2TX5CDU5S5Jz0A+UbirNQ+N
         kKU0vYThTSpyc5PTS+rw8vQoGkRDVt2vM+QjdfZhJ9j+kxfp4Jh5NRAsbOx5L8VrOpZ2
         afAdIXy0FI6HAH2cqcuEOf/8V+vEeRHnfufz8wj+tZOt336rB4SuZ19yJh8xVIb5XicH
         hPkxb8Ik7uM5XfjQGpOHkxJ1OnrgkH0mKuHNLo7W3f3RB+/Ftm2wjxEZ96qcm9E1VYF/
         EX1/9P415FICIfy34zzRkxaMvrpP4MhwIKYNZdH3Ji8b7CVYv+T9iTbAECFO967pPrH0
         Meug==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1765798752; x=1766403552; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:from:to:cc:subject:date:message-id:reply-to;
        bh=c+nTznDhynRMciuweJtM/4a/S4R8C2W9VEK7zOuSW/I=;
        b=czflBYbeCOr8gt8OV4JjHsd1J0O4ACz1vP05YipJU03jdgR23IIjY+wEGQtQjaW6FX
         dA30eBIf9zLUhMBVWcYF4YE0r146KTaIUGBKQ9VioD07pzOcch6qzvOaIJQw21WQ5Zyb
         gDz72DGZlSSCMEgyaVJegN3WGBGUe2Werq0yss1zhIZOItMuprFpTs/Hbli1pOphXEAF
         pYfoJqoC+zFXqT3ukSXuobjjDKd+SYn31O1ffbHnFRHUfrzF2ITDcpwDC6WBdqtG3UNj
         mm3orUOUQJLlsBjfQ6ogkckuF+ZOV1MqSfPDKnvnfG53KIxJb/E95X0xZT/BcmnkgB+H
         U5rQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1765798752; x=1766403552;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:x-gm-gg
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=c+nTznDhynRMciuweJtM/4a/S4R8C2W9VEK7zOuSW/I=;
        b=P8fQjjeZGfjFHuTOObTCGEx5WyEt78s8NUtKHumpA+YzLX7j3VLtRltH06ywdpY9TK
         9UsO7Vwa3sG83iJypI6s9cjcXgqAQI4f8LU8Q/kSxqzi3ec5L7e1yD607rg9GOFahj2z
         s3416jngGaQMTLHTVhtXIPSuyrN4TeU/8c77N4HPSr1d8+HEQVyM1pj/yOzl9ylfQ9BA
         Sn703e+QiKVPjY5/n9AhC1LPkdyOwVov9R+JHMuolYoD5/fGhQS5GTvsOUPU1ackqcoH
         gmEo9ippmGKz2gGScuZAxm4cfJ+QXOllwqQZUCydpcaXW8UqqhEk7Ka80znQprQmwPoU
         CTYw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXjAACXuEzcFtcGFuVvq0GdRkTITJXkqdeYrHEtHDT7Lo52moCX2U0HMGJA/XOXTbJuKWwrsw==@lfdr.de
X-Gm-Message-State: AOJu0YxPbuyuytbO2eLkfMklxC+mLNbrsE6AL1tn3RGFzOgkRzVtL9lH
	zxVHkxWm/0PV2WqBulOQZAyncX/iaVaCWsI21dyzQ4YGH9EunQXruA1J
X-Google-Smtp-Source: AGHT+IExQ0e61Ut/0SykeZ7Eg9LoEimcq/fShjk67ZQwhA6XDi1wFWMC/34uRnY+Iz8FNT8zd3imKA==
X-Received: by 2002:a17:90b:288b:b0:343:43bf:bcd7 with SMTP id 98e67ed59e1d1-34abdf3cdbemr9554502a91.13.1765798751627;
        Mon, 15 Dec 2025 03:39:11 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AWVwgWYbnm35vV8UK1SwZ9rzgh/t4f79lasqhHO+ehVgyCIyLg=="
Received: by 2002:a17:90b:1044:b0:34c:3502:8aca with SMTP id
 98e67ed59e1d1-34c35028c2dls788589a91.0.-pod-prod-00-us-canary; Mon, 15 Dec
 2025 03:39:10 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCXYrWSvHFmHuTHUsmvmPJsrjLKccYxVTeCDPdNSh0Q8pk3ixw77g4RTwW6svpoIY3q8yFH4VAobIho=@googlegroups.com
X-Received: by 2002:a05:6a21:6d88:b0:341:2c7b:ed13 with SMTP id adf61e73a8af0-369a83f9e30mr10303645637.5.1765798750219;
        Mon, 15 Dec 2025 03:39:10 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1765798750; cv=none;
        d=google.com; s=arc-20240605;
        b=DoO5O74udYucpsGnrgeclFUPS5YqLLR5XDZrx3dQJSkLzjOWVhWXiq/D46xuSNkvM4
         n+5OvtYIaOQ8sAQWW3OqXYzmJ5uSizCOfx/28ueMWa9oPXdOIL5oESU11EbxHaGVEr44
         OZX69JeXG0jqq9uWZmSp0V1nqDF6ZzbmjrJSnY3AwFrFNain8qOsDbrtrCjqcMqv6k3r
         e4rJ6xDjWyFEvq6lsvWOPWvYWwQKoT6LZTFU9hj2SkUDAdcYcX3A82Pmc5l+eiGpEyy4
         cMLCK+PiQ+0M4gA7snPP90lPtVoS0gx1SsOBCbQpPa1f/2D1u1eEtcFyy9zcdm/Sy5BV
         ZnPw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=H6vVzDCLpyU2LgSSSdcXlxGJ4GVOIz+XeeVoTvfPkdk=;
        fh=X/wpML4jQf//cFVR3ACX8Mu/XtVhztrTemg+81Fbe0E=;
        b=EF9wXtnVXho2ncIIlcKCPYXNFG0nl2ozs0LZrvWYhMeyL2QtBgOkcImJlXoTu6lz8p
         jZc3jrWfTfamNwDwBbbDoBnVF16b+QzMuj0hnoujCRI7ZsdSgFnyNOcDSYFcGGn0DOHv
         NTrINFLTvSLEe0+kmctMOAqjQh+xoc9Znp4/mDblg9UthZ9gSDxtlutkDcXTFOgL4Zjo
         GgwMOKDPvZWur7bROL06e16Q4/e8fwypl0wyRGsi+Ui67VCSZHKdgH3pvcOjjMkPAXi6
         YEVWyyKGSd6iYdkBIvM45XkmkmEUhzkBuqEuVf0MGSbTWtZPQ9lj8xclpb/tZ9lsQdIE
         DzAQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=U8mjiJIV;
       spf=pass (google.com: domain of bagasdotme@gmail.com designates 2607:f8b0:4864:20::42b as permitted sender) smtp.mailfrom=bagasdotme@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pf1-x42b.google.com (mail-pf1-x42b.google.com. [2607:f8b0:4864:20::42b])
        by gmr-mx.google.com with ESMTPS id d2e1a72fcca58-7f4c4ca695esi447828b3a.5.2025.12.15.03.39.10
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 15 Dec 2025 03:39:10 -0800 (PST)
Received-SPF: pass (google.com: domain of bagasdotme@gmail.com designates 2607:f8b0:4864:20::42b as permitted sender) client-ip=2607:f8b0:4864:20::42b;
Received: by mail-pf1-x42b.google.com with SMTP id d2e1a72fcca58-7bc0cd6a13aso1834465b3a.0
        for <kasan-dev@googlegroups.com>; Mon, 15 Dec 2025 03:39:10 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCXz+3nW7GdlM7evyputCnZ/w62C6ojmIT5iRRw7yUskRn0CKJ+bEwTDWtY+6N7psRnS8hAS/7svh/E=@googlegroups.com
X-Gm-Gg: AY/fxX45NfmSGJU1E3bMYtbbHDYd5g5enUutmVxVEuM1YwFzAYc5wldKzmbIQhJceDb
	4eR6sNMSWaTT3HwBkuTTYMIfVQyKWKvwU1DVrH+x860obGYAM7nSMMOpItxEyog57r7xLb45DyH
	cM6j0tN11oKbJYR09SylyflcJLrDlFYPGoqSG+UB4dkMtG7JlSTVEiezwAWX3GM0DSezce2cSWf
	RlZE2+DXuuP+egB6NAb9Tu3pCmr0finH9fWUmCR80s6enrsvIupSITKil++A2FFRAYTntuKK3wd
	5BkqeZjnHs9Ahc0cMym3CX/7tfoIV9bxSuRzNnHW4AQL/UBpXrIIqXG8T8AZJ4862wcENvWhfTW
	clDjRG6aw8bwKrcTlZ7LOVQxBIWuAPeF0blEwsJc4rln+pxFzucx3BQxnCsyp6sHzoWiTWTPhvM
	M2SnN39bfyz3r9s71BQBNb7w==
X-Received: by 2002:a05:6a00:1c83:b0:7b0:1d84:8634 with SMTP id d2e1a72fcca58-7f667f0be03mr9493916b3a.15.1765798749709;
        Mon, 15 Dec 2025 03:39:09 -0800 (PST)
Received: from archie.me ([210.87.74.117])
        by smtp.gmail.com with ESMTPSA id d2e1a72fcca58-7f4c22851besm12531845b3a.11.2025.12.15.03.39.07
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 15 Dec 2025 03:39:08 -0800 (PST)
Received: by archie.me (Postfix, from userid 1000)
	id 1D26D444B391; Mon, 15 Dec 2025 18:39:05 +0700 (WIB)
From: Bagas Sanjaya <bagasdotme@gmail.com>
To: Linux Kernel Mailing List <linux-kernel@vger.kernel.org>,
	Linux AMDGPU <amd-gfx@lists.freedesktop.org>,
	Linux DRI Development <dri-devel@lists.freedesktop.org>,
	Linux Filesystems Development <linux-fsdevel@vger.kernel.org>,
	Linux Media <linux-media@vger.kernel.org>,
	linaro-mm-sig@lists.linaro.org,
	kasan-dev@googlegroups.com,
	Linux Virtualization <virtualization@lists.linux.dev>,
	Linux Memory Management List <linux-mm@kvack.org>,
	Linux Network Bridge <bridge@lists.linux.dev>,
	Linux Networking <netdev@vger.kernel.org>
Cc: Harry Wentland <harry.wentland@amd.com>,
	Leo Li <sunpeng.li@amd.com>,
	Rodrigo Siqueira <siqueira@igalia.com>,
	Alex Deucher <alexander.deucher@amd.com>,
	=?UTF-8?q?Christian=20K=C3=B6nig?= <christian.koenig@amd.com>,
	David Airlie <airlied@gmail.com>,
	Simona Vetter <simona@ffwll.ch>,
	Maarten Lankhorst <maarten.lankhorst@linux.intel.com>,
	Maxime Ripard <mripard@kernel.org>,
	Thomas Zimmermann <tzimmermann@suse.de>,
	Matthew Brost <matthew.brost@intel.com>,
	Danilo Krummrich <dakr@kernel.org>,
	Philipp Stanner <phasta@kernel.org>,
	Alexander Viro <viro@zeniv.linux.org.uk>,
	Christian Brauner <brauner@kernel.org>,
	Jan Kara <jack@suse.cz>,
	Sumit Semwal <sumit.semwal@linaro.org>,
	Alexander Potapenko <glider@google.com>,
	Marco Elver <elver@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	"Michael S. Tsirkin" <mst@redhat.com>,
	Jason Wang <jasowang@redhat.com>,
	Xuan Zhuo <xuanzhuo@linux.alibaba.com>,
	=?UTF-8?q?Eugenio=20P=C3=A9rez?= <eperezma@redhat.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Uladzislau Rezki <urezki@gmail.com>,
	Nikolay Aleksandrov <razor@blackwall.org>,
	Ido Schimmel <idosch@nvidia.com>,
	"David S. Miller" <davem@davemloft.net>,
	Eric Dumazet <edumazet@google.com>,
	Jakub Kicinski <kuba@kernel.org>,
	Paolo Abeni <pabeni@redhat.com>,
	Simon Horman <horms@kernel.org>,
	Taimur Hassan <Syed.Hassan@amd.com>,
	Wayne Lin <Wayne.Lin@amd.com>,
	Alex Hung <alex.hung@amd.com>,
	Aurabindo Pillai <aurabindo.pillai@amd.com>,
	Dillon Varone <Dillon.Varone@amd.com>,
	George Shen <george.shen@amd.com>,
	Aric Cyr <aric.cyr@amd.com>,
	Cruise Hung <Cruise.Hung@amd.com>,
	Mario Limonciello <mario.limonciello@amd.com>,
	Sunil Khatri <sunil.khatri@amd.com>,
	Dominik Kaszewski <dominik.kaszewski@amd.com>,
	Bagas Sanjaya <bagasdotme@gmail.com>,
	David Hildenbrand <david@kernel.org>,
	Peter Zijlstra <peterz@infradead.org>,
	Lorenzo Stoakes <lorenzo.stoakes@oracle.com>,
	Max Kellermann <max.kellermann@ionos.com>,
	"Nysal Jan K.A." <nysal@linux.ibm.com>,
	Ryan Roberts <ryan.roberts@arm.com>,
	Alexey Skidanov <alexey.skidanov@intel.com>,
	Vlastimil Babka <vbabka@suse.cz>,
	Kent Overstreet <kent.overstreet@linux.dev>,
	Vitaly Wool <vitaly.wool@konsulko.se>,
	Harry Yoo <harry.yoo@oracle.com>,
	Mateusz Guzik <mjguzik@gmail.com>,
	NeilBrown <neil@brown.name>,
	Amir Goldstein <amir73il@gmail.com>,
	Jeff Layton <jlayton@kernel.org>,
	Ivan Lipski <ivan.lipski@amd.com>,
	Tao Zhou <tao.zhou1@amd.com>,
	YiPeng Chai <YiPeng.Chai@amd.com>,
	Hawking Zhang <Hawking.Zhang@amd.com>,
	Lyude Paul <lyude@redhat.com>,
	Daniel Almeida <daniel.almeida@collabora.com>,
	Luben Tuikov <luben.tuikov@amd.com>,
	Matthew Auld <matthew.auld@intel.com>,
	Roopa Prabhu <roopa@cumulusnetworks.com>,
	Mao Zhu <zhumao001@208suo.com>,
	Shaomin Deng <dengshaomin@cdjrlc.com>,
	Charles Han <hanchunchao@inspur.com>,
	Jilin Yuan <yuanjilin@cdjrlc.com>,
	Swaraj Gaikwad <swarajgaikwad1925@gmail.com>,
	George Anthony Vernon <contact@gvernon.com>
Subject: [PATCH 02/14] mm: Describe @flags parameter in memalloc_flags_save()
Date: Mon, 15 Dec 2025 18:38:50 +0700
Message-ID: <20251215113903.46555-3-bagasdotme@gmail.com>
X-Mailer: git-send-email 2.52.0
In-Reply-To: <20251215113903.46555-1-bagasdotme@gmail.com>
References: <20251215113903.46555-1-bagasdotme@gmail.com>
MIME-Version: 1.0
X-Developer-Signature: v=1; a=openpgp-sha256; l=950; i=bagasdotme@gmail.com; h=from:subject; bh=zaXx2zRxHwtjfsFTgY05kdIMv0UeQBx9b1FFiByYYYk=; b=owGbwMvMwCX2bWenZ2ig32LG02pJDJn2n4N0b+unPg8UXJx6+/+iP9I7pV1rdBYrPMm9NqGYl enCm2OnOkpZGMS4GGTFFFkmJfI1nd5lJHKhfa0jzBxWJpAhDFycAjCR246MDN8qzkf5GvF8u6h8 fK78A+u9Z2vjTS5MNJ2mcnT+/S07J0sxMvTNsLugLdEgeebaKl/Lt7ZFnv2pX8UvGPzINA+RNZw /gQsA
X-Developer-Key: i=bagasdotme@gmail.com; a=openpgp; fpr=701B806FDCA5D3A58FFB8F7D7C276C64A5E44A1D
X-Original-Sender: bagasdotme@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=U8mjiJIV;       spf=pass
 (google.com: domain of bagasdotme@gmail.com designates 2607:f8b0:4864:20::42b
 as permitted sender) smtp.mailfrom=bagasdotme@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;       dara=pass header.i=@googlegroups.com
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

Sphinx reports kernel-doc warning:

WARNING: ./include/linux/sched/mm.h:332 function parameter 'flags' not described in 'memalloc_flags_save'

Describe @flags to fix it.

Fixes: 3f6d5e6a468d02 ("mm: introduce memalloc_flags_{save,restore}")
Signed-off-by: Bagas Sanjaya <bagasdotme@gmail.com>
---
 include/linux/sched/mm.h | 1 +
 1 file changed, 1 insertion(+)

diff --git a/include/linux/sched/mm.h b/include/linux/sched/mm.h
index 0e1d73955fa511..95d0040df58413 100644
--- a/include/linux/sched/mm.h
+++ b/include/linux/sched/mm.h
@@ -325,6 +325,7 @@ static inline void might_alloc(gfp_t gfp_mask)
 
 /**
  * memalloc_flags_save - Add a PF_* flag to current->flags, save old value
+ * @flags: Flags to add.
  *
  * This allows PF_* flags to be conveniently added, irrespective of current
  * value, and then the old version restored with memalloc_flags_restore().
-- 
An old man doll... just what I always wanted! - Clara

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20251215113903.46555-3-bagasdotme%40gmail.com.
