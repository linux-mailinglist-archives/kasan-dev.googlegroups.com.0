Return-Path: <kasan-dev+bncBDBZNDGJ54FBBAFRQ7FAMGQEC3K3X5A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x640.google.com (mail-pl1-x640.google.com [IPv6:2607:f8b0:4864:20::640])
	by mail.lfdr.de (Postfix) with ESMTPS id 5CA31CC54D8
	for <lists+kasan-dev@lfdr.de>; Tue, 16 Dec 2025 23:09:07 +0100 (CET)
Received: by mail-pl1-x640.google.com with SMTP id d9443c01a7336-2a0dabc192esf56945635ad.0
        for <lists+kasan-dev@lfdr.de>; Tue, 16 Dec 2025 14:09:07 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1765922945; cv=pass;
        d=google.com; s=arc-20240605;
        b=XSD5YJy6HKPXnvwT5LhEefZmg+ZNlfZs35h0AKgZUbPqafgAEVCLXiBlexF6t3tZHm
         NS9KdUXQrD+FcvICgjXfGuh0OD09b/z8R/qjyt23rePQ6E3nNR4GG1XT8bx9Qf0NPUFt
         9Vi6I/HN7QV2RbYaCsiql75DL+pZVyAjgzAsCLKIdPct3BoonWHz5zG0gsRVXxZPB88/
         aTrWWA3elQu7Ju2LMMJ+x4ZN+xM4lNJLOQ8WqQSwVGHeZutZJ89DHL4Pnugou8DG+Fdh
         iHmWtkmmvAKlCcpkqhrtWLQq878fOKJw0AtOxcSfQn+DrPZ0uImres6u5+feWYN5yYq0
         6Xlg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:subject:cc:to:from:date:dkim-signature;
        bh=d0YKCVCwOX4fPJhEIEBuqkcCAH6aqFO09bD/n3d6wqA=;
        fh=ZDX7Oz86tGH+34zsG4SrAzi+42RZ3Vhmu9w4aaE3+84=;
        b=WiY0Sf93BTuvNHoRl4yiQLHSiBZokwsXKYKETKSx2Im05cB8vmzP1Kr58/ljr/IoMD
         NTFQq3pjLHBp6ZKQ0gHW0spHQuIQF5XUFom36aSVitbC/eZnEC1HtFwrHcIoAgf1We4j
         nhrOqFDdYjACLMp54GQ7kOl1SQmAxeeO5p0OdtELtpPtkWuNtQnxe6W/PQM3iCiL8iRc
         Md2lq8Q5yKWLl8e4RlT/wJxVcaCElz1GP6kpLdq2aXcUx0y7HLZnewd1+ZOiJdodeFZx
         eOb1ijt9m9mntHp2KlLgMzowYxwLM/rfu6YtLFQsEucr3484M2Njm/n+EHWh0mmK0F86
         0Lmw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=oqiadpWD;
       spf=pass (google.com: domain of kuba@kernel.org designates 2600:3c04:e001:324:0:1991:8:25 as permitted sender) smtp.mailfrom=kuba@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1765922945; x=1766527745; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:subject:cc:to:from:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=d0YKCVCwOX4fPJhEIEBuqkcCAH6aqFO09bD/n3d6wqA=;
        b=LSSg9qlQGPXbqU9daD+ubtUzSYhLHF++m8XUkqyMD0+FXU2UYqCoYteYqxZP2F7L7E
         liRVTsQadPuSJtubV7i6GbfRMyKJ2pnjT/mC9lrRwOhd8pS03zF6c8pYmIxykaEpEuNN
         JT+p5TdbonSEZtJwoRCDFpzJ2DT02I7FybDNEmgNZU/uWpgaWW/nSRJHPkLP2zySF8h3
         s8G9gXwsTDQj/bekq/E0f2IpdvTiI4Gn1uw5NZoytiooaBifPUwFtwRACCkEac+O8bYr
         Q7rC9jQeqAiyY5eaG3sXNUqC5MW5hu11rqkQpg5P++dipVCkdkDuDPHeDBar0nlTdtkG
         ON1g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1765922945; x=1766527745;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:subject:cc:to:from:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=d0YKCVCwOX4fPJhEIEBuqkcCAH6aqFO09bD/n3d6wqA=;
        b=GlQe5EU06j1NsB190bbV6dSUGvMBsQuQkyOWwXXdbYqoC6tByyVFRYp1NvOB9DQNDN
         2ExlTLe4BKZ5yNLEXdhCONcPFNSE13Z76z9/54G5CE4SxbKUVbAHmrZB/zLjcfKbv1F+
         485Xg59I+WKCCCqu4YN6PLYKO/i9XG48ekUzJogDW9i6odqu+0ohNFZ2LNDyMA5lZce/
         fRnYD0eimgwbVy4XHA6yO9RYka7Zr4z7d3CwTMy/kIHBVYgFCs/mmvoKPXaSzq17L0S3
         /SUvWtV7CgwBpVTCqcA0RPNfaJkP59imHHP94246Y9ZWSQwMRNoo72skPIgxJyeaSd54
         yEQw==
X-Forwarded-Encrypted: i=2; AJvYcCX+L250jAMVAZXgxYJjgHNwKa2mm5eUXdkzEALee+LwDYdtigA31TsS/ZTQNL9XlW9jk+VHWw==@lfdr.de
X-Gm-Message-State: AOJu0YwpjoqDFgp2J0+Uu150OMimnxmVPaZizkvTo5ZqB/EmPCfiXUMb
	ZOqnfrNkWF0dfjXvd86NzsdPIRoZgIUYcpq6MHgCeZSbLUZ8m796vatb
X-Google-Smtp-Source: AGHT+IFfCM2WKbtNB6rhhiQUxyx8HB+1Vi4LWbXs2+UfX+hooZmtv4zBt9jH0eYs1IUy2R513ls8JA==
X-Received: by 2002:a17:903:2ece:b0:295:4936:d1e9 with SMTP id d9443c01a7336-29f23c7b7e3mr154819925ad.36.1765922945186;
        Tue, 16 Dec 2025 14:09:05 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AWVwgWaqRj2amG2NMk+rEYw36cSFm3ka1knr7yHcKS+8KJtxCw=="
Received: by 2002:a17:903:23c5:b0:29b:96c1:2de3 with SMTP id
 d9443c01a7336-29f233558c1ls28551285ad.0.-pod-prod-05-us; Tue, 16 Dec 2025
 14:09:03 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCX6ZZwQOrIkrw67nwc76jIzNs4MDOaAfZzGBgr+Ggg3LViU30AQqiU8Tta90/Wc1zNh1XQvUXkTAAI=@googlegroups.com
X-Received: by 2002:a17:902:f647:b0:2a1:47e:1a34 with SMTP id d9443c01a7336-2a1047e1b30mr80903695ad.0.1765922943385;
        Tue, 16 Dec 2025 14:09:03 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1765922943; cv=none;
        d=google.com; s=arc-20240605;
        b=Uf8ltpE1YsI9VxCBLy6CcjNMVYQT9S174hFBxddHZbmUXxC6LYhaXHdosKoPzxRD87
         DWm5U2BA9O6NwNyRcgUmbSq2OVHJt85mLfsw0otb1YYrjpX5gChU5oDpvYmjG2RtSkz/
         gpzqBMEkYwzRAumb1ewwVqEhKnA+qv5JvPCMxof3whIWbRHIH/qvTyCJBA2hxMOEc4P7
         67Kp21StS2kX5UzJqZqlWphw+YwOMEr3VqMvCFycneo+/cksecy7XweuN38T8az/FODl
         KnQb8+9q0GdZkzjgEoUPrnAN1YNhhwof5kR1HbjupnL2H8B5wJQfwYm/6UuOKmhBA/Zq
         dsIQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=B0kVLZK7YMAGW4+NymplABFlILpQoztpjaegZ/yGPWg=;
        fh=qRzGpm1eJ0bxQEU4uoWiTuQalZBXN44PARReVgWCxko=;
        b=SdskuSe52KMvHwqSz2s3ZmGSKg/xy5kbj6Alo+9WzajM2weB//f+psQYn5oj3MePjq
         hg/LSeTaQiBi/5HKfWIdJiOqaWRADw0Szg0pojxaCMEhXe/eX6ZRVz+e/5rDYsJecHMl
         FetKUXUjO7ytUq5mNMDQup0UgIsSyMD2RTgSt6Mfw1aPLEolpLDmnSg7TbG07ho858si
         tKLucfxKVAgbjHs27typix6sAcdbnVo00t20A/0CrDYAdxxzOH47gEogvNTvUChO7tZI
         +3gZ2xPtYgA2/oHsq1/1rAo1Nux4IVXgJeXoopya0bS83dydcvzZbU6AbADXsOjHQFOb
         WB5g==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=oqiadpWD;
       spf=pass (google.com: domain of kuba@kernel.org designates 2600:3c04:e001:324:0:1991:8:25 as permitted sender) smtp.mailfrom=kuba@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from tor.source.kernel.org (tor.source.kernel.org. [2600:3c04:e001:324:0:1991:8:25])
        by gmr-mx.google.com with ESMTPS id d9443c01a7336-2a105d76f47si2837885ad.5.2025.12.16.14.09.03
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 16 Dec 2025 14:09:03 -0800 (PST)
Received-SPF: pass (google.com: domain of kuba@kernel.org designates 2600:3c04:e001:324:0:1991:8:25 as permitted sender) client-ip=2600:3c04:e001:324:0:1991:8:25;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by tor.source.kernel.org (Postfix) with ESMTP id E059860097;
	Tue, 16 Dec 2025 22:09:01 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 4509EC4CEF1;
	Tue, 16 Dec 2025 22:08:58 +0000 (UTC)
Date: Tue, 16 Dec 2025 14:08:57 -0800
From: "'Jakub Kicinski' via kasan-dev" <kasan-dev@googlegroups.com>
To: Bagas Sanjaya <bagasdotme@gmail.com>
Cc: Linux Kernel Mailing List <linux-kernel@vger.kernel.org>, Linux AMDGPU
 <amd-gfx@lists.freedesktop.org>, Linux DRI Development
 <dri-devel@lists.freedesktop.org>, Linux Filesystems Development
 <linux-fsdevel@vger.kernel.org>, Linux Media <linux-media@vger.kernel.org>,
 linaro-mm-sig@lists.linaro.org, kasan-dev@googlegroups.com, Linux
 Virtualization <virtualization@lists.linux.dev>, Linux Memory Management
 List <linux-mm@kvack.org>, Linux Network Bridge <bridge@lists.linux.dev>,
 Linux Networking <netdev@vger.kernel.org>, Harry Wentland
 <harry.wentland@amd.com>, Leo Li <sunpeng.li@amd.com>, Rodrigo Siqueira
 <siqueira@igalia.com>, Alex Deucher <alexander.deucher@amd.com>, Christian
 =?UTF-8?B?S8O2bmln?= <christian.koenig@amd.com>, David Airlie
 <airlied@gmail.com>, Simona Vetter <simona@ffwll.ch>, Maarten Lankhorst
 <maarten.lankhorst@linux.intel.com>, Maxime Ripard <mripard@kernel.org>,
 Thomas Zimmermann <tzimmermann@suse.de>, Matthew Brost
 <matthew.brost@intel.com>, Danilo Krummrich <dakr@kernel.org>, Philipp
 Stanner <phasta@kernel.org>, Alexander Viro <viro@zeniv.linux.org.uk>,
 Christian Brauner <brauner@kernel.org>, Jan Kara <jack@suse.cz>, Sumit
 Semwal <sumit.semwal@linaro.org>, Alexander Potapenko <glider@google.com>,
 Marco Elver <elver@google.com>, Dmitry Vyukov <dvyukov@google.com>,
 "Michael S. Tsirkin" <mst@redhat.com>, Jason Wang <jasowang@redhat.com>,
 Xuan Zhuo <xuanzhuo@linux.alibaba.com>, Eugenio =?UTF-8?B?UMOpcmV6?=
 <eperezma@redhat.com>, Andrew Morton <akpm@linux-foundation.org>,
 Uladzislau Rezki <urezki@gmail.com>, Nikolay Aleksandrov
 <razor@blackwall.org>, Ido Schimmel <idosch@nvidia.com>, "David S. Miller"
 <davem@davemloft.net>, Eric Dumazet <edumazet@google.com>, Paolo Abeni
 <pabeni@redhat.com>, Simon Horman <horms@kernel.org>, Taimur Hassan
 <Syed.Hassan@amd.com>, Wayne Lin <Wayne.Lin@amd.com>, Alex Hung
 <alex.hung@amd.com>, Aurabindo Pillai <aurabindo.pillai@amd.com>, Dillon
 Varone <Dillon.Varone@amd.com>, George Shen <george.shen@amd.com>, Aric Cyr
 <aric.cyr@amd.com>, Cruise Hung <Cruise.Hung@amd.com>, Mario Limonciello
 <mario.limonciello@amd.com>, Sunil Khatri <sunil.khatri@amd.com>, Dominik
 Kaszewski <dominik.kaszewski@amd.com>, David Hildenbrand
 <david@kernel.org>, Peter Zijlstra <peterz@infradead.org>, Lorenzo Stoakes
 <lorenzo.stoakes@oracle.com>, Max Kellermann <max.kellermann@ionos.com>,
 "Nysal Jan K.A." <nysal@linux.ibm.com>, Ryan Roberts
 <ryan.roberts@arm.com>, Alexey Skidanov <alexey.skidanov@intel.com>,
 Vlastimil Babka <vbabka@suse.cz>, Kent Overstreet
 <kent.overstreet@linux.dev>, Vitaly Wool <vitaly.wool@konsulko.se>, Harry
 Yoo <harry.yoo@oracle.com>, Mateusz Guzik <mjguzik@gmail.com>, NeilBrown
 <neil@brown.name>, Amir Goldstein <amir73il@gmail.com>, Jeff Layton
 <jlayton@kernel.org>, Ivan Lipski <ivan.lipski@amd.com>, Tao Zhou
 <tao.zhou1@amd.com>, YiPeng Chai <YiPeng.Chai@amd.com>, Hawking Zhang
 <Hawking.Zhang@amd.com>, Lyude Paul <lyude@redhat.com>, Daniel Almeida
 <daniel.almeida@collabora.com>, Luben Tuikov <luben.tuikov@amd.com>,
 Matthew Auld <matthew.auld@intel.com>, Roopa Prabhu
 <roopa@cumulusnetworks.com>, Mao Zhu <zhumao001@208suo.com>, Shaomin Deng
 <dengshaomin@cdjrlc.com>, Charles Han <hanchunchao@inspur.com>, Jilin Yuan
 <yuanjilin@cdjrlc.com>, Swaraj Gaikwad <swarajgaikwad1925@gmail.com>,
 George Anthony Vernon <contact@gvernon.com>
Subject: Re: [PATCH 00/14] Assorted kernel-doc fixes
Message-ID: <20251216140857.77cf0fb3@kernel.org>
In-Reply-To: <20251215113903.46555-1-bagasdotme@gmail.com>
References: <20251215113903.46555-1-bagasdotme@gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: kuba@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=oqiadpWD;       spf=pass
 (google.com: domain of kuba@kernel.org designates 2600:3c04:e001:324:0:1991:8:25
 as permitted sender) smtp.mailfrom=kuba@kernel.org;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
X-Original-From: Jakub Kicinski <kuba@kernel.org>
Reply-To: Jakub Kicinski <kuba@kernel.org>
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

On Mon, 15 Dec 2025 18:38:48 +0700 Bagas Sanjaya wrote:
> Here are assorted kernel-doc fixes for 6.19 cycle. As the name
> implies, for the merging strategy, the patches can be taken by
> respective maintainers to appropriate fixes branches (targetting
> 6.19 of course) (e.g. for mm it will be mm-hotfixes).

Please submit just the relevant changes directly to respective
subsystems. Maintainers don't have time to sort patches for you.
You should know better.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20251216140857.77cf0fb3%40kernel.org.
