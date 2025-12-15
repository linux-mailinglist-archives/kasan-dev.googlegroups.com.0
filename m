Return-Path: <kasan-dev+bncBCJ455VFUALBBGPL77EQMGQEBOQI3SQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1039.google.com (mail-pj1-x1039.google.com [IPv6:2607:f8b0:4864:20::1039])
	by mail.lfdr.de (Postfix) with ESMTPS id CBF2CCBD971
	for <lists+kasan-dev@lfdr.de>; Mon, 15 Dec 2025 12:48:43 +0100 (CET)
Received: by mail-pj1-x1039.google.com with SMTP id 98e67ed59e1d1-34c43f8ef9bsf1434791a91.1
        for <lists+kasan-dev@lfdr.de>; Mon, 15 Dec 2025 03:48:43 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1765799322; cv=pass;
        d=google.com; s=arc-20240605;
        b=bCj/Ukx5GwXfxRJlCG3vdXZeVYT3TZWt8X29sjbaAAThKzDnwIMhoqpsoL/V4PDjy0
         vcyUGnq2LIp8HdqsubigNzQ9iDMD4juc9AZ9NCKDuLTmlViQl6NBtLv4r6wOz0RXcaM5
         h66ABt5Kaaaz82t3BP6XnytUPD8Y27Lx4cmryG/vZg33meae4zJafXSmlTdsPcHKhG07
         xq6V9MYFzOGTridnfgorbxE/L9HsmJOY6+kQfaLmtn4SCn20b3NdJoc95YcFo70kuskm
         znNFIwZIdohi6IFTPmjaqrVfYoMUbrof6h/kBazG5Rcg/L1xNWC1JgL9Z6xncs8rWrLX
         SZug==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature
         :dkim-signature;
        bh=dsqQEXo4G5S5o8CL9pTgUFjFDyBkpfknc8rNBwztW50=;
        fh=EsRAFgtsidLxrC7wPigXJEHde/7hg1SHVpNmG6TChxA=;
        b=driVGhEqsdseLqig6T1IYZzPZz5qgAIV7TS5tWOvOU0ugBsEDneu5MAB8BT+9HiQxW
         Z5B4gd6JhKR3FfW9zBsgpI9yrzEBu+zXTNpTfj9VPouko0jDX4wM8m9eymqiIsMEeB1i
         UFOXeYkJdRZShrVRoKYeprYi3YNUI5a9EDGhwyyAVKfoWWbf6+WBOmZqj6a36VMM+l9Q
         QM/WbWLDuJyDOqH1wQhxzmiicGWQWbFMjI62/EJXy67JJE+SJQFvI+34qpo3zknjCbld
         DA4Kn2Zfi6TAIIGWEQrBEYWADb54ublFAspkOt2mlQPtw6Qo/NEhlRsI47sj+2SQy8UR
         SYCQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=Z8MSEluL;
       spf=pass (google.com: domain of bagasdotme@gmail.com designates 2607:f8b0:4864:20::630 as permitted sender) smtp.mailfrom=bagasdotme@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1765799322; x=1766404122; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=dsqQEXo4G5S5o8CL9pTgUFjFDyBkpfknc8rNBwztW50=;
        b=mzOsmw/gkuulfkG7DnXy9BBtW6WRUdLUwa49Boft6C5ZEMXJykHyM4rTIIZoy+OZvV
         NGe5Racy1vzbmtIo/3gKhKcrmEYCrDFAgMmjss3u87btrU1w0AFJz2jjiBRWUwjeHKEf
         G4yUm/rxkd07Uz4ToCTmHPY/cUpVaJ5OMLa05EzDYTP2HHfSbvt+r7rTOgZBSbsKRK29
         KDy3YPCZzSBvFMgHIK8VX9ogM/4WEqgcLE/LbWoqrIdGOqaVxoAdq+LoWwT56CkoCJQO
         nlYZRFo5UvP52uDRDst0WJBhDyuw4Vcv4a19vMBzPMvjPzEWFTo0HIxviJwcYqnxsjGZ
         Hjiw==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1765799322; x=1766404122; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:from:to:cc:subject:date:message-id:reply-to;
        bh=dsqQEXo4G5S5o8CL9pTgUFjFDyBkpfknc8rNBwztW50=;
        b=F1FhdCa1nSwwRxyPCVd2riHd9qni0jVkyhTU/ZhKcXVtKEBj9ZtNO83spCDcrUdFtT
         GeO2z/oCKJM5rpNw4xKSN/1Jx0koiq/Xl8PU/C9nbwSUrrk5xZEHqsVmK8rAc0dfXKDw
         5iJhggL7VadQjyNLDfhksHqeE8osAWwcOCexXdR5u69ARHcC7FerNVZ9N+ZaXGV7LYAV
         LVAjc34phQIpH8TLYQAMN5POCnOsZWU4L1FZGronYsjsg1xkp02O/En1x88zEBNHY1nn
         OVQPWBwijYDGcgXigaa9Sc/4DbpVnrZTRqYXvwup6McZqfu7ByqtFi664/JheRSC2P/C
         n28w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1765799322; x=1766404122;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:x-gm-gg
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=dsqQEXo4G5S5o8CL9pTgUFjFDyBkpfknc8rNBwztW50=;
        b=OLmXh0fWwHyq1kjzi67ykv4M9ZNDBtky4e0zzLKcEhNAbGqvh1/UZEem7Q2ewkByep
         pDm/RttGzJeBBcML43aoL3Tl8rrRDQfio1bdW/2d01jXLXsgROSVI28OIBw0fjDWzJ+5
         aGQZ+f2oHvaPLVydtZA9XcWA8VsZHvzXazpjZj7VKcEicuIlDtKYUM+7c32sqlhTCxkO
         0FhGGofLLYTN+a7IG0EHRxiRNk5sZ7TqhxiiRyxAUFL8PYoYG/RnS5oz7jREvr28b7BE
         AIuPHbTp02XVWIp1SILng+OUF6HfwpSbFSz0GSZZgQYUGO7IMdBZkcudHHTbn+Wcjw0x
         0Dtg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVwxkfOyzikKFtLGYOC83e92BtG2sihtgwdoT8vy1vTYl6WL+MzTKDRwVWEmC287D0PdEH1bw==@lfdr.de
X-Gm-Message-State: AOJu0YwcXkkfnkJn5n1G1nHiqL3MoFvKhA7e6T9usbtH1ePcEF5bDtC0
	uDOcJrVL2vxzbMPVmja4t1MnvhziDmhuZup4KyaTGhzfGaKsedJHIwxJ
X-Google-Smtp-Source: AGHT+IFw/zaDgFtWSDu9kCb/3g/Vh48ysVy0IV0PaT5ZfUqNSONkrxYt1TE0YIJeXuPMKmpnqCAudg==
X-Received: by 2002:a17:90b:2f0c:b0:343:87b3:6fbb with SMTP id 98e67ed59e1d1-34a926230f7mr11502011a91.8.1765799322101;
        Mon, 15 Dec 2025 03:48:42 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AWVwgWb3FDq9kVpdRs1K/ez8EwB2aJLqORsQkAquobbxtrEZ7Q=="
Received: by 2002:a17:90b:1247:b0:34a:4aa1:8b1f with SMTP id
 98e67ed59e1d1-34abce8ceadls1361846a91.1.-pod-prod-00-us; Mon, 15 Dec 2025
 03:48:41 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCU8ajKt0BAEKAWVRhh1P6YQG0FdjD+YVp+/5RR3R9wmb/JveKKfVzWNFguH6efBGofsZnPp2mdCAto=@googlegroups.com
X-Received: by 2002:a17:90b:50ce:b0:343:7410:5b66 with SMTP id 98e67ed59e1d1-34a926aa028mr12427995a91.11.1765799320902;
        Mon, 15 Dec 2025 03:48:40 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1765799320; cv=none;
        d=google.com; s=arc-20240605;
        b=lvXeTx+Te5bArc4ldZm4SIDh3SEzwZQR/pgjEIo55OXk35/fDpXrkwKlM0bHVthhZA
         tcerAG//XJi7IsFJguBhmjFjqOBOmRjo+KuNJpusGvPEOnelBBA6ZnBNa9vr9wvGCW2G
         ay0cElU4s9//J0N1oZUrR3I6qSRMXetsOp1s453wKcRS9sksS+GwOqKfbim2rX9CCSXo
         8LxqaF4MsKrHnSv8qbhpvh2phOPO/7UPUBXS3V4LT4uPeXFl3Zq8BSQF3//wXR9YtZp9
         j2xvVt3eNjSkxn68/o1uUDgVt2WKd6ijDwGl42pIQhi0rVeslpkYSgxLeRp3L6s+AzcF
         pdPQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=TrKHAwDmwEWPzZzAT0wzFml+5He+R0bXqVhPFRZE9SA=;
        fh=gmXZ0tGa/lEtOP99KjR5JjY3hyr7IMm6DD4u+sDgJ+g=;
        b=dtEmnfaRWj6vQuirgAk8P7SdEtyJKdy5ct9mNKkb61TZ8/DHGh0qhU6CAMoumzbzr5
         FrmCZCwGT+AWjVo3UnKL8cM2MQyYVUtUAA0xTSZX45TFZQvBDQ+683uP+9JQrJqcLkXi
         w469H2J1tXc7ERhHHkR4SaPsNZqiHKtw+kRebfzw8purrf/qoNeVo6wGJSua2hzASwil
         t3hEiifLHDj2ewwBNLaGrXRkpO9qBgRTT80h8BJouKYs9jugWDApERDys4fE9Lnkjf82
         Sb+MQN09CMnakKl20NZOq2zVpt2tJASmNbT2c01zEmEkD4kQbZYS2gXHGW34q1bcw5tI
         B8zA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=Z8MSEluL;
       spf=pass (google.com: domain of bagasdotme@gmail.com designates 2607:f8b0:4864:20::630 as permitted sender) smtp.mailfrom=bagasdotme@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pl1-x630.google.com (mail-pl1-x630.google.com. [2607:f8b0:4864:20::630])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-34abe2521edsi168158a91.1.2025.12.15.03.48.40
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 15 Dec 2025 03:48:40 -0800 (PST)
Received-SPF: pass (google.com: domain of bagasdotme@gmail.com designates 2607:f8b0:4864:20::630 as permitted sender) client-ip=2607:f8b0:4864:20::630;
Received: by mail-pl1-x630.google.com with SMTP id d9443c01a7336-2a0c09bb78cso8903325ad.0
        for <kasan-dev@googlegroups.com>; Mon, 15 Dec 2025 03:48:40 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCUntglhab2+k+t65yY6YCjAatufIs8mjYQDmK0ZBbOLY6ww+O4rXRPltiRk+CP8O79c+J2l+t+j3tI=@googlegroups.com
X-Gm-Gg: AY/fxX6RHJfQMUODAraYjkEXknRFUybg4igZJnsv2/7kdBWmrCqkSNuL0Q/N5jLrJow
	IhaKEGQX/2Ko8DznqzWOWQyahxMucG4mUECcty6Z+SJ1bBJXNfCqCq2FdDq8InPoHGrtjSLh+eK
	yBqkvr4beZrGtQVfdmpZA8UGqqHpUkDoj74G/havLppPccMgOD8WsfP5ie4/Zvv4alAgPWXwX2a
	g9dvjBfygVEV/LZzPmTe0AlKLMLuVpoDhzz2ytGmmKhfcfg/yGn4Sob6DCJKxkRg4O8t5cSgZnx
	L82T966OGl9wlQGFa6qFku+koHyMvZJ/C0k89HRiL/0YKA3v3q8yS+1y4IU/JjnNEolMGfzfyZd
	dSVv8SYSF95fo2U6b/zHIS4oaWT0RSe650qz4buGWPVdgmavuKRgmBEPPRKFiwVr7YIm4cKeuUt
	pxwKDgJm/ZHNU=
X-Received: by 2002:a17:902:ef02:b0:2a0:835f:3d5b with SMTP id d9443c01a7336-2a0835f40dbmr89139405ad.6.1765799320408;
        Mon, 15 Dec 2025 03:48:40 -0800 (PST)
Received: from archie.me ([210.87.74.117])
        by smtp.gmail.com with ESMTPSA id d9443c01a7336-29ee9b376e2sm133357725ad.14.2025.12.15.03.48.39
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 15 Dec 2025 03:48:40 -0800 (PST)
Received: by archie.me (Postfix, from userid 1000)
	id 357B044588D8; Mon, 15 Dec 2025 18:39:06 +0700 (WIB)
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
Subject: [PATCH 11/14] drm/gem/shmem: Describe @shmem and @size parameters
Date: Mon, 15 Dec 2025 18:38:59 +0700
Message-ID: <20251215113903.46555-12-bagasdotme@gmail.com>
X-Mailer: git-send-email 2.52.0
In-Reply-To: <20251215113903.46555-1-bagasdotme@gmail.com>
References: <20251215113903.46555-1-bagasdotme@gmail.com>
MIME-Version: 1.0
X-Developer-Signature: v=1; a=openpgp-sha256; l=1239; i=bagasdotme@gmail.com; h=from:subject; bh=NBybN5/snlW67CYY0LDf5z9mjlB8/ZE5MQWmfMjzEtk=; b=owGbwMvMwCX2bWenZ2ig32LG02pJDJn2n4OX/nxidPxCa7t5fuOD8HMfrQSuP1hub/O7ZcKpR 3k2jWdLOkpZGMS4GGTFFFkmJfI1nd5lJHKhfa0jzBxWJpAhDFycAjCRtAcM/yunTjs9ydWYJypu wYcH6cfFNi1X5dYSuyPxxuv3me1JcpKMDBs+vU9uutHzrUbncPwy+73MjZlbOwIfHrr54bGU4uz aOwwA
X-Developer-Key: i=bagasdotme@gmail.com; a=openpgp; fpr=701B806FDCA5D3A58FFB8F7D7C276C64A5E44A1D
X-Original-Sender: bagasdotme@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=Z8MSEluL;       spf=pass
 (google.com: domain of bagasdotme@gmail.com designates 2607:f8b0:4864:20::630
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

Sphinx reports kernel-doc warnings:

WARNING: ./drivers/gpu/drm/drm_gem_shmem_helper.c:104 function parameter 'shmem' not described in 'drm_gem_shmem_init'
WARNING: ./drivers/gpu/drm/drm_gem_shmem_helper.c:104 function parameter 'size' not described in 'drm_gem_shmem_init'

Describe the parameters.

Fixes: e3f4bdaf2c5bfe ("drm/gem/shmem: Extract drm_gem_shmem_init() from drm_gem_shmem_create()")
Signed-off-by: Bagas Sanjaya <bagasdotme@gmail.com>
---
 drivers/gpu/drm/drm_gem_shmem_helper.c | 3 ++-
 1 file changed, 2 insertions(+), 1 deletion(-)

diff --git a/drivers/gpu/drm/drm_gem_shmem_helper.c b/drivers/gpu/drm/drm_gem_shmem_helper.c
index 93b9cff89080f9..7f73900abcbb9d 100644
--- a/drivers/gpu/drm/drm_gem_shmem_helper.c
+++ b/drivers/gpu/drm/drm_gem_shmem_helper.c
@@ -96,7 +96,8 @@ static int __drm_gem_shmem_init(struct drm_device *dev, struct drm_gem_shmem_obj
 /**
  * drm_gem_shmem_init - Initialize an allocated object.
  * @dev: DRM device
- * @obj: The allocated shmem GEM object.
+ * @shmem: The allocated shmem GEM object.
+ * @size: shmem GEM object size
  *
  * Returns:
  * 0 on success, or a negative error code on failure.
-- 
An old man doll... just what I always wanted! - Clara

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20251215113903.46555-12-bagasdotme%40gmail.com.
