Return-Path: <kasan-dev+bncBC7OBJGL2MHBBNXU77EQMGQECPYOMXA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103c.google.com (mail-pj1-x103c.google.com [IPv6:2607:f8b0:4864:20::103c])
	by mail.lfdr.de (Postfix) with ESMTPS id F0150CBDB42
	for <lists+kasan-dev@lfdr.de>; Mon, 15 Dec 2025 13:08:24 +0100 (CET)
Received: by mail-pj1-x103c.google.com with SMTP id 98e67ed59e1d1-34c314a062asf4772177a91.2
        for <lists+kasan-dev@lfdr.de>; Mon, 15 Dec 2025 04:08:24 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1765800503; cv=pass;
        d=google.com; s=arc-20240605;
        b=cK1zxJfPP4wpJIC28tZkeiTqYW8sf4qggfhMVmmGnF1DP/apppzJ9vT/gE906jn+Da
         /NkLhLKLnDudXYDvhc66Nvulm/8dXSzB3lF52TG9SJFlZQ5UCn2FdY9ArZOChOO/MB4T
         t+h4rgrZ5qGUKJPFt3OcKGycUZcdgOEy3g+lZKU6bZUGwVno5riw9oZBlZdsdXVnNVeB
         ey1A6MPMoarMVzNW2a2o3PQpF/K5ulQramobVDcpa6zdy2k4gGOgiPzNV5gbGCdPrXGB
         I7NzKEUqpIForlVIcw2mkksNlPL1JZGXLgHw26zxTGqrA1AUoxM3R+tlm6vJStWjgq2o
         LxyQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=qFe8z/5z41SGuFv3+YVAU+51lawuxIZyT0DPi2/Uxow=;
        fh=A3BZ8tlL2Xs127Ii1ul0v832UahvcRFhdEzhFBXeWbk=;
        b=IRk7DK9UoG4T29lCd32psnBs0/nt0Gb4JgcN3Eie63Pwe3Qj5fRXw0B/Ol/Ds7NwSq
         Qxzr1EDXMhU2nNGCy4+EVRqGuWcTYDcQox2hgwT7hmBfxUEu3IU8AMt7tkMTWxtZlp+b
         OTB3aVIGIBQS26Oasq+VMi7TWOF9o4xx1kPFLD2sbI72MBb4l4RqdaXIoOS2LcCIHEOp
         2jIyXJYHr+upqXdVYnJSqwTRyBNmD0uzNJ7dZmC4nS54O3oS0BdwT3ZmdpcjSUaZ/CmS
         Q8i3FfrrkT0/w3vjyfV7t0T7gzVIX6gOeVEYAR0Z6B1aCIc0ZvEZJ7RjEMHwWQaEMh2t
         LIRQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=SG2PS3Jg;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::62c as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1765800503; x=1766405303; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=qFe8z/5z41SGuFv3+YVAU+51lawuxIZyT0DPi2/Uxow=;
        b=c81LIFck9Tw/7wbpdVtAf5ac3KbuyiuslqJVkxQ0jIm9kFK1VU5VvL0rr5toN6N/Kq
         vq7M4f+eQPU/fM8tPwP08NjmcS3bJCwpVQkUSLYz1dYDRphUeZVNijrI32E6Zt96fobF
         4kJd18b+nugGoCkZmc/xBQvx65A9+Azv4T3NGFXU8/O2m7jF4dmbxpnQ4ZIKy9qNFFko
         hhPEfs3bjeh540uivbtiSz7OKc20PuNmoPLCrka49GKdsyr2dWtEwkVbJByXdaNoikBm
         6uO0gnbPkzdDy4h+4OATR/A8tYeNAGFiiACXbOThRQljgNoIpHm3D5bDCW9O4Y5/l6zy
         FiZg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1765800503; x=1766405303;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:x-gm-gg
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=qFe8z/5z41SGuFv3+YVAU+51lawuxIZyT0DPi2/Uxow=;
        b=e4+Nu4i/4pFKVK4J74QxugDXmLUETKzZVO5IjJW66ll+GMYstBDZ4aXPgKXFmmSmId
         J99bvQRQhVy/RYrdXDUgOtGmifkYAjf6gWsCsgDG2yKt/PR+u9x0OMo8zyUJHKC+ysZQ
         z6aUpm/RgYAQwb5L7dID0wq31Ni+juFmJCfAO/thxjBwXy07gsu8e3SAeKe2sxudXTWR
         vDbmRQczPf4utS4uf4PcyxhzCDydg3h2D0lLLzof503jU8WxK+l4i0hAICr5EqoNerfv
         V5x8tiLkxtYBONGQOY1LdGy2BK/US58rHe8bqdp+gyt/4E2IXCXq6/C68tqMaMFd7RCV
         nnDg==
X-Forwarded-Encrypted: i=2; AJvYcCW0EZPfwd1mqnHNhjdlAM/A7dLCZnlFzoraT1wV7Q1gkCs5pqzbc3e2sVYh+girz5XtsUSLVA==@lfdr.de
X-Gm-Message-State: AOJu0Yy4paw+ZoSPbUIXMFl1AtFCNXMcpNUD3eWFYSnKyvotlkt/bfcV
	m/0p3H8bUT4gyA0OSAOBRViiQT7wugsds8M7dJMohAN3WJqTGsssnvTE
X-Google-Smtp-Source: AGHT+IGbkZZHZX4fySVtMCXuTYzqdfXi4c3Raar9QkmtequE791oEcEvn/LJXznla/mtHG/ij4Ftww==
X-Received: by 2002:a17:90b:5211:b0:32e:3830:65d5 with SMTP id 98e67ed59e1d1-34abd787a6fmr9221953a91.36.1765800503311;
        Mon, 15 Dec 2025 04:08:23 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AWVwgWbu5f95yZmAg8Z5kC7dQFB8xNj7NUuZ4ChOvFlRPnpsRg=="
Received: by 2002:a17:90a:f413:b0:340:5090:ca5a with SMTP id
 98e67ed59e1d1-34abcc8300els2161050a91.1.-pod-prod-02-us; Mon, 15 Dec 2025
 04:08:22 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCVyVCa9c5VgX+Um0YRKn6CG2rclxdXxGWXSPD/aGojM8pVqK8ZOQOfScuHcfRxnJfRH7tSfLcWBMQo=@googlegroups.com
X-Received: by 2002:a17:90b:2542:b0:343:eb40:8dca with SMTP id 98e67ed59e1d1-34abd75ba02mr9301352a91.19.1765800501839;
        Mon, 15 Dec 2025 04:08:21 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1765800501; cv=none;
        d=google.com; s=arc-20240605;
        b=gdSDHOmUSPwy3+TcCV1Q691mtESP7KDQli8YI2/MeUWn8VyJ9Zh2zF8FXFhDPTqbxh
         hjAYa+tb4cGIwUxsNMQz3BvW0ITlX6r1P0iCJc2Kq+QW4yrbAa/zpZfIzakkTQvoDCSQ
         zLtvCSmOkD1hb4Q3P1jjJdtGNu4URXRwfP9AAlgdgwkizswi4w9YxYp67SGdZZs7DH/o
         f5cNWlt99BqyCeNa8AnJ2pqPp7pqbtZT+HpE+E+uN2fS6CPwA3p5/oWRcj0zQIXIy54M
         vkZcTQYKFyU83ZEoNCKeBi/SIP09iyhQBewLybPjDwBzok45nQdE6yrDjdLkKwGCa9AY
         UBgw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=+DGkbwvSveRrQtSlxFukYMul6SfDciYSPOsqEu5ZQPQ=;
        fh=ZDJ5S0CIBSDkDruGWFKGklnujmgvXkcvedqWIJ10ZKk=;
        b=J58Cqt+p+sYREZ4WeGIJeOEFMp1tcw9VD/obXMk1PCbJEh2N2nUg/ot8UPG5bGbV1t
         LEWxDUWMqGowCFd9eFRJhdEvtfEzH2bQqBkUJr4irFfVXyrh6lkAfArNGtRAmpzTcmiq
         YXUhJuA4HueqfCP00omaAHTQcEjPbJkksnSH12IcE6+R89upvAeYIcCuBrjVNfQv18En
         weD4xVBEnT/dLPUN7ptkSLbPY6r5kwRt9Dlmgw+uG0S05d2Y2m+2KV8N9JeYyAl2njAi
         6aF5/F0tHxz9QnWnjEA7zkwLTRMLvGiBVHTvMaHIMYhVVrRDy4AD+cB7oV4EkBmlnX2b
         gslg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=SG2PS3Jg;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::62c as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pl1-x62c.google.com (mail-pl1-x62c.google.com. [2607:f8b0:4864:20::62c])
        by gmr-mx.google.com with ESMTPS id 41be03b00d2f7-c1361b76c72si190935a12.0.2025.12.15.04.08.21
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 15 Dec 2025 04:08:21 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::62c as permitted sender) client-ip=2607:f8b0:4864:20::62c;
Received: by mail-pl1-x62c.google.com with SMTP id d9443c01a7336-29f0f875bc5so44315015ad.3
        for <kasan-dev@googlegroups.com>; Mon, 15 Dec 2025 04:08:21 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCUfgKlB90L/d/2vNVw/eICkE4IL6smdHOmFar/8Tf/8OybW+tM0Q4xfrP0ixosg9JoNz1QxyIE1Afo=@googlegroups.com
X-Gm-Gg: AY/fxX7YCCHY3zXfSRU4Lt3kuwsBtOQ/yugD+zKM1/71Zh0l6r1apuJXEDTbZPDyqSO
	XOvzyReHiSBhIY9Rd6JnSfCb2+A+Afz41RcOBxbIdMDUloMbLBtOAyeTqVtRa/fL6vZ/9d8F3p3
	aF7HhK6MvUyJHYwy5REu9AZ4L2BqZ23W75cPU5DT9mqnmLKSb7q0dBrPC6TY2fiUEngiaLItjQG
	EbF6zYBHvsCn3v+5wwQqk6/IULIpXMS6esdlGX31Ef/fUbkU7J8oJTN0W0x3A9LpwLkzObSv9DY
	pQyixIhyegwuXYe2/nUcFc0rag2H2hQRUv7b
X-Received: by 2002:a05:701a:ca0d:b0:11b:8fc9:9f5d with SMTP id
 a92af1059eb24-11f34c4d15emr7306064c88.30.1765800500924; Mon, 15 Dec 2025
 04:08:20 -0800 (PST)
MIME-Version: 1.0
References: <20251215113903.46555-1-bagasdotme@gmail.com> <20251215113903.46555-6-bagasdotme@gmail.com>
In-Reply-To: <20251215113903.46555-6-bagasdotme@gmail.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 15 Dec 2025 13:07:43 +0100
X-Gm-Features: AQt7F2pEt11ob6m3jn_EvmNyiM9lcI5ir1gIqaEopvbMbWpYo3dEgZbn6PIAiFk
Message-ID: <CANpmjNNrHYCPp19A_FPeFY1kSTuyS0W_zjo21AUrmjqjqcYa0A@mail.gmail.com>
Subject: Re: [PATCH 05/14] mm, kfence: Describe @slab parameter in __kfence_obj_info()
To: Bagas Sanjaya <bagasdotme@gmail.com>
Cc: Linux Kernel Mailing List <linux-kernel@vger.kernel.org>, 
	Linux AMDGPU <amd-gfx@lists.freedesktop.org>, 
	Linux DRI Development <dri-devel@lists.freedesktop.org>, 
	Linux Filesystems Development <linux-fsdevel@vger.kernel.org>, Linux Media <linux-media@vger.kernel.org>, 
	linaro-mm-sig@lists.linaro.org, kasan-dev@googlegroups.com, 
	Linux Virtualization <virtualization@lists.linux.dev>, 
	Linux Memory Management List <linux-mm@kvack.org>, Linux Network Bridge <bridge@lists.linux.dev>, 
	Linux Networking <netdev@vger.kernel.org>, Harry Wentland <harry.wentland@amd.com>, 
	Leo Li <sunpeng.li@amd.com>, Rodrigo Siqueira <siqueira@igalia.com>, 
	Alex Deucher <alexander.deucher@amd.com>, =?UTF-8?Q?Christian_K=C3=B6nig?= <christian.koenig@amd.com>, 
	David Airlie <airlied@gmail.com>, Simona Vetter <simona@ffwll.ch>, 
	Maarten Lankhorst <maarten.lankhorst@linux.intel.com>, Maxime Ripard <mripard@kernel.org>, 
	Thomas Zimmermann <tzimmermann@suse.de>, Matthew Brost <matthew.brost@intel.com>, 
	Danilo Krummrich <dakr@kernel.org>, Philipp Stanner <phasta@kernel.org>, 
	Alexander Viro <viro@zeniv.linux.org.uk>, Christian Brauner <brauner@kernel.org>, Jan Kara <jack@suse.cz>, 
	Sumit Semwal <sumit.semwal@linaro.org>, Alexander Potapenko <glider@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, "Michael S. Tsirkin" <mst@redhat.com>, Jason Wang <jasowang@redhat.com>, 
	Xuan Zhuo <xuanzhuo@linux.alibaba.com>, =?UTF-8?Q?Eugenio_P=C3=A9rez?= <eperezma@redhat.com>, 
	Andrew Morton <akpm@linux-foundation.org>, Uladzislau Rezki <urezki@gmail.com>, 
	Nikolay Aleksandrov <razor@blackwall.org>, Ido Schimmel <idosch@nvidia.com>, 
	"David S. Miller" <davem@davemloft.net>, Eric Dumazet <edumazet@google.com>, 
	Jakub Kicinski <kuba@kernel.org>, Paolo Abeni <pabeni@redhat.com>, Simon Horman <horms@kernel.org>, 
	Taimur Hassan <Syed.Hassan@amd.com>, Wayne Lin <Wayne.Lin@amd.com>, Alex Hung <alex.hung@amd.com>, 
	Aurabindo Pillai <aurabindo.pillai@amd.com>, Dillon Varone <Dillon.Varone@amd.com>, 
	George Shen <george.shen@amd.com>, Aric Cyr <aric.cyr@amd.com>, 
	Cruise Hung <Cruise.Hung@amd.com>, Mario Limonciello <mario.limonciello@amd.com>, 
	Sunil Khatri <sunil.khatri@amd.com>, Dominik Kaszewski <dominik.kaszewski@amd.com>, 
	David Hildenbrand <david@kernel.org>, Peter Zijlstra <peterz@infradead.org>, 
	Lorenzo Stoakes <lorenzo.stoakes@oracle.com>, Max Kellermann <max.kellermann@ionos.com>, 
	"Nysal Jan K.A." <nysal@linux.ibm.com>, Ryan Roberts <ryan.roberts@arm.com>, 
	Alexey Skidanov <alexey.skidanov@intel.com>, Vlastimil Babka <vbabka@suse.cz>, 
	Kent Overstreet <kent.overstreet@linux.dev>, Vitaly Wool <vitaly.wool@konsulko.se>, 
	Harry Yoo <harry.yoo@oracle.com>, Mateusz Guzik <mjguzik@gmail.com>, NeilBrown <neil@brown.name>, 
	Amir Goldstein <amir73il@gmail.com>, Jeff Layton <jlayton@kernel.org>, 
	Ivan Lipski <ivan.lipski@amd.com>, Tao Zhou <tao.zhou1@amd.com>, 
	YiPeng Chai <YiPeng.Chai@amd.com>, Hawking Zhang <Hawking.Zhang@amd.com>, 
	Lyude Paul <lyude@redhat.com>, Daniel Almeida <daniel.almeida@collabora.com>, 
	Luben Tuikov <luben.tuikov@amd.com>, Matthew Auld <matthew.auld@intel.com>, 
	Roopa Prabhu <roopa@cumulusnetworks.com>, Mao Zhu <zhumao001@208suo.com>, 
	Shaomin Deng <dengshaomin@cdjrlc.com>, Charles Han <hanchunchao@inspur.com>, 
	Jilin Yuan <yuanjilin@cdjrlc.com>, Swaraj Gaikwad <swarajgaikwad1925@gmail.com>, 
	George Anthony Vernon <contact@gvernon.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=SG2PS3Jg;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::62c as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com;       dara=pass header.i=@googlegroups.com
X-Original-From: Marco Elver <elver@google.com>
Reply-To: Marco Elver <elver@google.com>
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

On Mon, 15 Dec 2025 at 12:39, Bagas Sanjaya <bagasdotme@gmail.com> wrote:
>
> Sphinx reports kernel-doc warning:
>
> WARNING: ./include/linux/kfence.h:220 function parameter 'slab' not described in '__kfence_obj_info'
>
> Fix it by describing @slab parameter.
>
> Fixes: 2dfe63e61cc31e ("mm, kfence: support kmem_dump_obj() for KFENCE objects")
> Signed-off-by: Bagas Sanjaya <bagasdotme@gmail.com>

Acked-by: Marco Elver <elver@google.com>

Thanks!

> ---
>  include/linux/kfence.h | 1 +
>  1 file changed, 1 insertion(+)
>
> diff --git a/include/linux/kfence.h b/include/linux/kfence.h
> index 0ad1ddbb8b996a..e5822f6e7f2794 100644
> --- a/include/linux/kfence.h
> +++ b/include/linux/kfence.h
> @@ -211,6 +211,7 @@ struct kmem_obj_info;
>   * __kfence_obj_info() - fill kmem_obj_info struct
>   * @kpp: kmem_obj_info to be filled
>   * @object: the object
> + * @slab: the slab
>   *
>   * Return:
>   * * false - not a KFENCE object
> --
> An old man doll... just what I always wanted! - Clara
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNNrHYCPp19A_FPeFY1kSTuyS0W_zjo21AUrmjqjqcYa0A%40mail.gmail.com.
