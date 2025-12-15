Return-Path: <kasan-dev+bncBCJ455VFUALBBHPL77EQMGQESUVYOSY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3f.google.com (mail-oo1-xc3f.google.com [IPv6:2607:f8b0:4864:20::c3f])
	by mail.lfdr.de (Postfix) with ESMTPS id BD88CCBD97E
	for <lists+kasan-dev@lfdr.de>; Mon, 15 Dec 2025 12:48:46 +0100 (CET)
Received: by mail-oo1-xc3f.google.com with SMTP id 006d021491bc7-6576fd62dffsf4868537eaf.2
        for <lists+kasan-dev@lfdr.de>; Mon, 15 Dec 2025 03:48:46 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1765799325; cv=pass;
        d=google.com; s=arc-20240605;
        b=W6qBotsqJb7McxbrvEqkc/GLqix0KP8LeJJiv6KCElbJdyuP0E9L3lZ1nzzo6Ous4P
         cxfw0r46DIMOTf+gtSla5dRsLRXhoUYuKwNnk0T+3JHiD+N2CafwnueCca0wSZRskfn6
         CKbQ1PyiJOfitFP3EV+D8ZlvOeSJ4XfGUZlR4F4OChjEnH6I3qLqzHphZr8esa+3gMmV
         qDUFCviX+b/YuX1oT0voU7PeGLvmawvZ6Qkd6mghAvVeJ8XpofI216QgBUofszNDM1p5
         3NGUPhNB+o+KLdXrS/1S8SWaev5DLLf6smcgAAy8YXu03hKQpnJzPsReLm3kZFa48dsG
         AomQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature
         :dkim-signature;
        bh=gWIHsMXtmH9eYdBgOlxlThe1RYm+V3N9IAoCdVx4YZw=;
        fh=Ye7sjGl9DpPmFyrtpXsZG2fXybzNZUF6b3tBMefyG2I=;
        b=YUg1WO6n/SuAlNugBnZCNiMK28Ce6m5yVl3Jf8UMI7K2SzEz5AwIrM/tOXA7MnMCBt
         rOfxTqpgc8G/MHcJBQ8YBdpP9V4jJ9nQIni7oLW8bj6z0QAsbVtJ82putGQMCwx255g4
         QrL/nBE9MNBtJH5+sKA1akMGNeDFtfejbrzMYcNWByxWcUsY2UBop823/MuvLYnIJo1g
         3NkhyK3OMB61We6OMMFZdIqW5+IXAea0EsjBf4U/Oqf4jEhaeWJOpj9S+GBaNSdADVn+
         Ks/ga5W+32kaQygXwoMQV2FXCvQlPEXIitutdX/F3+LSA/AMlKr1ZivjRtBPKLiBPr1n
         2mJg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=ecTPcmsv;
       spf=pass (google.com: domain of bagasdotme@gmail.com designates 2607:f8b0:4864:20::62f as permitted sender) smtp.mailfrom=bagasdotme@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1765799325; x=1766404125; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=gWIHsMXtmH9eYdBgOlxlThe1RYm+V3N9IAoCdVx4YZw=;
        b=rm0zA42BDaPejurwY/2JziMZVf0wecfvI4d8ILna+RUN1LtU0qiTLfJrQUU8WG3L9N
         a4BEZN8hKVcC8y7GvVp7CDmND8yRELu0wYbAZ7UTX6ZLk79xDVM1KLTHu/J1CmCFv7o7
         3HxgF2VK+Vt5FwzgjRYQlceATsiZj+Ms9Qjd2bhI9OKoR3TA1yHaYiM8oZ0tKvH10pf2
         WCRbqSLzNJ4oqr10YITKTo/rh7YDqiea0LoLV2NW+BSvloBHNXne8QSlX5zpsQqanTxN
         0WR3relBzmBVwdqLxr4K+NuzBmiGzfBAywX+KSXqJdoe2uTVYytaI6axfm2zQJY8ZvZd
         aFdQ==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1765799325; x=1766404125; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:from:to:cc:subject:date:message-id:reply-to;
        bh=gWIHsMXtmH9eYdBgOlxlThe1RYm+V3N9IAoCdVx4YZw=;
        b=mizHQKxHMZd8aqZPad/8z530My9ZbQnNGqS079/ATbyMoUbf71YSHkmfaYFfJLO0gB
         3lC68DZLesksV7PiehD2pEIfZ6/LK/7405OUxdLLc6svfqiKibe9eGH4mq+zYwU3T4qO
         PqaorH8b6HFPEcCMT9wQutUISfmpQuKlC67xgGG8IuiywVwJLXrttRhyPQoBiFLhcl86
         kHkQ7ViEVdna0/oDYNmJqzHjHrXaOLC3iZb1fig2PMc4QmGnGfw0bU/hhzJ4luR30AIM
         W4awsHCDBrFxs8jCw4m1dvy/O+fV96oUoZ/aFkAdz2MraMHw3EHbT5YyMNCfl1ZlY0zL
         F/NA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1765799325; x=1766404125;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:x-gm-gg
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=gWIHsMXtmH9eYdBgOlxlThe1RYm+V3N9IAoCdVx4YZw=;
        b=FBKikklEEedHNNne+PO74M46oElIZjVmK/P/7GER8lD0+C1LCw5mdsnEFvZ2KfRTz6
         NRhExaa7j+WRhALZAbwdfdqTgA2VmbPYtpTUTVmxCyGpUuFE5ykpfU6qkRpuz/GDZVzk
         Jlr+MrWtTq2IwqLknYLMfRcYFyJfcsOX+l8S+XVNz8Cy+4zGMCtPS1AfKCr06WhBkN11
         3Haf0IVZKE6tpTgCruiCRiAdhbtM2lk6H4sSmAC8wdKBwQIpm0LdhbicuYUIB2Qh8AD1
         ah++yTUChQmOqjkWaRfd4Ut8AaL+jgGTjQ7ctT8w14XjDu1ORar8Mvkw4UZ1InroDd49
         Di2A==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUYgSnI1B+8gL5mLs84UjKHI6qw7EH1+TmfYwICzrd8HRiqkl/vjkhDZu8WX8f7FuAZI2JZVg==@lfdr.de
X-Gm-Message-State: AOJu0YwDVJc846Ph1uA1RJzfGf/iINFYCDwqw3GrtdYuI5xDK1es8pvo
	mDZ1bt5mh5RVyozDF1jlFYpXpfGjFG0Y3NlrOcTP+njvrMBWlA9r7wr+
X-Google-Smtp-Source: AGHT+IGiobkFoeW6tNifjNyEYYKxXoxYPqlBpG8B/7wNXZhGh1tRHf9FU6yhT0n2IxbbbigGp73bXA==
X-Received: by 2002:a05:6820:3095:b0:657:71ec:544f with SMTP id 006d021491bc7-65b455bd285mr4616248eaf.2.1765799325371;
        Mon, 15 Dec 2025 03:48:45 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AWVwgWbSSMQR0+0EFwK/YAwlMgaWaF/dI2JdKtQPMBrpDfrqGw=="
Received: by 2002:a4a:b6c2:0:b0:657:906e:22a3 with SMTP id 006d021491bc7-65b43a68529ls1762290eaf.1.-pod-prod-01-us;
 Mon, 15 Dec 2025 03:48:44 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCVqjNRoDxBaXPigf1ERerGAFoO2prmOlhzo4XIbMnJskWD2R5vGgZmnmxOwMRapjq64AvTsRORzQDM=@googlegroups.com
X-Received: by 2002:a05:6830:254b:b0:7ca:ea23:f851 with SMTP id 46e09a7af769-7caea241681mr5641426a34.13.1765799323986;
        Mon, 15 Dec 2025 03:48:43 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1765799323; cv=none;
        d=google.com; s=arc-20240605;
        b=KwRTY+AERpLrs1mxn6Lf5CFaHuUnDkwoylUkQRoeR5n8hPX3hEql1nwu6GtEzVDdO9
         t+Yr54jex0rcjRwmeG0p8+VH9CNcMVSxUcSTFljDZNcB9l01tvLZjvfRkI78Tvu8Z1qf
         OJ3x+XTsrWGn3/JsVFe6vdIlkUzDpUPyRzssXNU4FaO1UbtoxogrKFAvbf8I24S6XgKY
         PBFR3nfkd1dql9GgfqCxkt80OHotv3vqR9wS0A74XLTlDyfx0032dDR5cjMTXiwkRXmY
         DEqXR4agFTOs6EIInfyJ+9swWwnz3FfMMIs2RPV/qzI/OfGo5WR2F9vve2SuARK96RmR
         BGdw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=HPi/WFWmImBnVQgsxNvJvJyvieXM1xBFzKoWis67Gg4=;
        fh=5z6SM72PRh+SV942DbA1t+7ne0RSdNWHupilgX9HgEs=;
        b=LlbcnZEAt2Zb+WEum78uKLqdmRQy7u4gkPRpjuhmnzx1r+F1p2g8hXQfefXI1amLhS
         A3sUC8Mgfl7v3eZbQhUZVoAEpEqVJicyTHAeyvhVmWxkY90R6lFQwkEHiKfGp72+p35x
         XsKu7mp+BNGe44Wb+XwrrIMkBitKiL/mPRKj4pRPNaNww6ChxDrfKV0Woz8AfYQ5smuT
         PtzslBbsUPJ0D/a9GXm0tbOtfkGpWQv8l51j4V9k/X5haMvjpI1132XDzf+WPd9kPDwo
         L33hFVeAfTauL3PXoeBaX4zA/lI41r5T5m4nKrJiV97YkFF5XS9Se/CGqNuies6Ts1ne
         d9VQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=ecTPcmsv;
       spf=pass (google.com: domain of bagasdotme@gmail.com designates 2607:f8b0:4864:20::62f as permitted sender) smtp.mailfrom=bagasdotme@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pl1-x62f.google.com (mail-pl1-x62f.google.com. [2607:f8b0:4864:20::62f])
        by gmr-mx.google.com with ESMTPS id 46e09a7af769-7cadb2cbd91si611479a34.5.2025.12.15.03.48.43
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 15 Dec 2025 03:48:43 -0800 (PST)
Received-SPF: pass (google.com: domain of bagasdotme@gmail.com designates 2607:f8b0:4864:20::62f as permitted sender) client-ip=2607:f8b0:4864:20::62f;
Received: by mail-pl1-x62f.google.com with SMTP id d9443c01a7336-2a0bae9aca3so17573065ad.3
        for <kasan-dev@googlegroups.com>; Mon, 15 Dec 2025 03:48:43 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCWiOPKMzeSHoWXIsmsFUW/BiNXPh6qAlCoofUEVfRSYIn+yPIXWEKsMWBchi1NzvizTLdT3T18R9gY=@googlegroups.com
X-Gm-Gg: AY/fxX7ehvvViuBs7ndaQPvkpudu8vFpFXuDsYP/9fSscMHvL/jRGh/dzMak41NeVPo
	x/F71plk/EyARvlipj92VyMD1SGUnZHkUHoWK7bY7sYTC4E4+timKihhpBf4x4nr5X4z3XDwYFJ
	wX9HQDdFPo6blJ/DlAw8dD8CW8DqBzJEsU4L82ao8ip4H1ENtdc0weuQMFaIo0REEUW/zW7PI/t
	NF1Vyhqp84v4+Ol1jTdI3W5M4C3vkKLPvjAL8E/X0iHcjE6RSIXm8r81OzlJZHFr/btJK6Chz+P
	OX8O//ODLea4DiYraOeN6bCNHZIHfcyqfzdCATUW/vc1h0dw467WdupQVKyCHv57lnNFQNus7BT
	ZVtqS/yayuk6vSFlnLs543byOxgeEoT7SXJt3z0uHGbPZNvrqXgXiylpkqPjbPrNOGiUnLQSf31
	Kyx6ep3BqnFQE=
X-Received: by 2002:a17:902:e5c1:b0:2a0:9084:3aff with SMTP id d9443c01a7336-2a090843d40mr77419135ad.61.1765799323500;
        Mon, 15 Dec 2025 03:48:43 -0800 (PST)
Received: from archie.me ([210.87.74.117])
        by smtp.gmail.com with ESMTPSA id d9443c01a7336-29eea016f80sm133066335ad.60.2025.12.15.03.48.41
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 15 Dec 2025 03:48:42 -0800 (PST)
Received: by archie.me (Postfix, from userid 1000)
	id 60C6F447330B; Mon, 15 Dec 2025 18:39:07 +0700 (WIB)
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
Subject: [PATCH 13/14] drm/gpusvm: Fix drm_gpusvm_pages_valid_unlocked() kernel-doc comment
Date: Mon, 15 Dec 2025 18:39:01 +0700
Message-ID: <20251215113903.46555-14-bagasdotme@gmail.com>
X-Mailer: git-send-email 2.52.0
In-Reply-To: <20251215113903.46555-1-bagasdotme@gmail.com>
References: <20251215113903.46555-1-bagasdotme@gmail.com>
MIME-Version: 1.0
X-Developer-Signature: v=1; a=openpgp-sha256; l=1611; i=bagasdotme@gmail.com; h=from:subject; bh=j4BXJJMKUhATWUahdKX0lx9i399WYlQDn9Ep3/iweMY=; b=owGbwMvMwCX2bWenZ2ig32LG02pJDJn2n0OumS5gNW5/3GqYe0vV4BnvxdVlFyqnrRPWP9PpP u3FMcecjlIWBjEuBlkxRZZJiXxNp3cZiVxoX+sIM4eVCWQIAxenAEykPJ/hF9Pft9/+BqzKa/W8 rdg9vSMz5a6N4PnTByKYzgTJnWZ/P5Hhn+aKvLS4vrtB9w7NNb77cZZgzZ2+T776O+w93L/xls2 5xAgA
X-Developer-Key: i=bagasdotme@gmail.com; a=openpgp; fpr=701B806FDCA5D3A58FFB8F7D7C276C64A5E44A1D
X-Original-Sender: bagasdotme@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=ecTPcmsv;       spf=pass
 (google.com: domain of bagasdotme@gmail.com designates 2607:f8b0:4864:20::62f
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

Commit 6364afd532bcab ("drm/gpusvm: refactor core API to use pages struct")
renames drm_gpusvm_range_pages_valid_unlocked() to
drm_gpusvm_pages_valid_unlocked(), but its kernel-doc comment gets
stale, hence kernel-doc complains:

WARNING: ./drivers/gpu/drm/drm_gpusvm.c:1229 function parameter 'svm_pages' not described in 'drm_gpusvm_pages_valid_unlocked'
WARNING: ./drivers/gpu/drm/drm_gpusvm.c:1229 expecting prototype for drm_gpusvm_range_pages_valid_unlocked(). Prototype was for drm_gpusvm_pages_valid_unlocked() instead

Fix them up.

Fixes: 6364afd532bcab ("drm/gpusvm: refactor core API to use pages struct")
Signed-off-by: Bagas Sanjaya <bagasdotme@gmail.com>
---
 drivers/gpu/drm/drm_gpusvm.c | 4 ++--
 1 file changed, 2 insertions(+), 2 deletions(-)

diff --git a/drivers/gpu/drm/drm_gpusvm.c b/drivers/gpu/drm/drm_gpusvm.c
index 73e550c8ff8c98..fcfbe8c062bf6d 100644
--- a/drivers/gpu/drm/drm_gpusvm.c
+++ b/drivers/gpu/drm/drm_gpusvm.c
@@ -1216,9 +1216,9 @@ bool drm_gpusvm_range_pages_valid(struct drm_gpusvm *gpusvm,
 EXPORT_SYMBOL_GPL(drm_gpusvm_range_pages_valid);
 
 /**
- * drm_gpusvm_range_pages_valid_unlocked() - GPU SVM range pages valid unlocked
+ * drm_gpusvm_pages_valid_unlocked() - GPU SVM range pages valid unlocked
  * @gpusvm: Pointer to the GPU SVM structure
- * @range: Pointer to the GPU SVM range structure
+ * @svm_pages: Pointer to the GPU SVM pages
  *
  * This function determines if a GPU SVM range pages are valid. Expected be
  * called without holding gpusvm->notifier_lock.
-- 
An old man doll... just what I always wanted! - Clara

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20251215113903.46555-14-bagasdotme%40gmail.com.
