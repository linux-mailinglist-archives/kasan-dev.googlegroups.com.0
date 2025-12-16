Return-Path: <kasan-dev+bncBDOJZOXA5ABBBCF3QPFAMGQEZTEXMCY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x73b.google.com (mail-qk1-x73b.google.com [IPv6:2607:f8b0:4864:20::73b])
	by mail.lfdr.de (Postfix) with ESMTPS id 3C7C8CC0DCC
	for <lists+kasan-dev@lfdr.de>; Tue, 16 Dec 2025 05:18:18 +0100 (CET)
Received: by mail-qk1-x73b.google.com with SMTP id af79cd13be357-8b2f0be2cf0sf1399411285a.0
        for <lists+kasan-dev@lfdr.de>; Mon, 15 Dec 2025 20:18:18 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1765858697; cv=pass;
        d=google.com; s=arc-20240605;
        b=gvHQGKB9nXN3UyvtwLp9+apZ2XBuxpBwUQ9edhwUYW+T8FshzxPLEUxJ1DMdPIcrci
         6Kp6ISeM5H8KbWV/QsfUP3fY7n0QNXkPqbk5VSTTqidN0ZvdEPlI4u84EPbSEzHwm+f1
         Hb5CU4sYxRIvtPad8XauIAyLI+pMlcdY4b5AJYGLd3GKJf2Hr3/bZaV03uG9iEQmnlEW
         +NjmVqdqp44UHvuc8Zw95A7NpSsdKNGFel8Itxbkmzc8Km+fMD8r56ULExU/IehS3BrC
         KcINsJ6uQ6Ec7AwHmQp9m9oK+023SC913iT6qzv5cHQJNoajp4oPIQ8iPUiip9VbfFYT
         ydDw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=e3OEE81cJzlKJ/ZU7AMxrb25wvA5ykrOrozLKhtk6bQ=;
        fh=5KwHSMHLBEiPa2KMdaKAU63rBK90OEURHi5lGgP5YGA=;
        b=TSASxAL7NZYSxzwzdLCKtIz1US/BPk3JPKb4jyloEROxjYEXBj64xmxUHxbNX07lA2
         9ZZRrbw0gXC9Je4ppIQSA4rJcvq165k6qyS5ZtWQeuIoIiS89oOZyYwEybagRj7hs9s6
         GvnQi05kEdX14FcT1hqvBaA502tTnD5hSYI1acow2ficzRdA1KbAwXjHVh+TCLd9BIcy
         xQ0bUFCpoviuVQNmsW0y+4EEDrOjUU8oESaJ/jYDZycvuspHIsS5nb5qjYstYQN7qDac
         95NXhskizncXfwmOJd6uWJ/jcm0XPwHZntITcPoSlPUF0I1rqk5V8ijJrOTE+b98fvhx
         K57w==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=A5NjXvGD;
       spf=pass (google.com: domain of jasowang@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=jasowang@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1765858697; x=1766463497; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=e3OEE81cJzlKJ/ZU7AMxrb25wvA5ykrOrozLKhtk6bQ=;
        b=u8KcjZaH+JWH7UMTECwG1gYBzn3qUOlqA69apv51S+XwjXclBDA0Nzud2MkoEJirZw
         qk1MZZhgtnH0KirbYSiR+lqNNHRXguUmh3uaFfBH0cBkPsG6iWjM6rLlZhEzo7wdk5Xq
         U63d1nXpszmDlLmuvyYSWNVyDH1ZrgFBIdO+DrQ+BbmgR5y2JVakuw3kIx1FN10miadn
         6MyLDOjNmH2spN2Yjqn7HcSQb1yy8xK4pYO1a7kDsVJJmft3SKXqrP26xLsdnCKln5Yp
         SRjVpNXBarhRtq9YLbd5bDYAikiGNtgAXtZHZBtBJHl2jXpv6uAfhqV7+l8q/cB6MvW6
         1GPw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1765858697; x=1766463497;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-gm-gg:x-beenthere
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=e3OEE81cJzlKJ/ZU7AMxrb25wvA5ykrOrozLKhtk6bQ=;
        b=BVf9ufCyH+Pthb5jSY4MFlO+0wLwSFADnCmQaPffyBw8k2hj0pjBf0WpjMwLXucn/H
         zZmfaXsNqi45v/78fj3Af6+FnMj6LPHHjSp7MK5/7l+pHNzutIuNRCSIsNFIRYkCsimH
         DIyLVL78MsnBdTlry5VfrYyUpYtAr7cTt/f1D7ttwRibUfJWgFCNkGCSEXMBZuZAzukT
         MscOdbWqqzqrfeCmLZLQPTh21e8PuEhKmys1xkAPB3niCgS8bVGwX67ORocI68hU/CpE
         PdjMsM+NY/EAl+mT5dkzF7tL8Tp2o/UzhDBxPgMVnUbRtunKM3YqO7GDYXvqAS7I4JiT
         0HkA==
X-Forwarded-Encrypted: i=2; AJvYcCUYC4g0wBS8ztss9WujmXB5P52ZhgsEopbGqEhTA4yxKCDOe5qYgmqH6ssRGjTigl9soBrqYA==@lfdr.de
X-Gm-Message-State: AOJu0YxkmvHrP0mYAYLtPPBxN9OArWUkloPaSAt8ReeHT7pLqZEt1+W5
	PpPUniVgmZ7UzjfV/O6SEc6G2EheS0sGf6RPXqYAbqwzIDBydhaV7d9h
X-Google-Smtp-Source: AGHT+IHdVcqrrKI0spiz7kxUhC4SZbngftkOxIZYX1bX/1dknqz3p8MQJdWKP9YqdMysFBZAEY0yrQ==
X-Received: by 2002:a05:620a:45a3:b0:815:630d:2cbd with SMTP id af79cd13be357-8bb39dc3fb5mr1682916785a.34.1765858696674;
        Mon, 15 Dec 2025 20:18:16 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AWVwgWZH7a8u6dQFJYv4fGs1cOF7TqfkDydOtKhH4kLV9En4kw=="
Received: by 2002:a05:6214:3009:b0:888:1f20:6a87 with SMTP id
 6a1803df08f44-8887c92e31als24699726d6.0.-pod-prod-04-us; Mon, 15 Dec 2025
 20:18:16 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCXuIDAnIIJqt6X4m6WAa1VbKXYKOvvHc9P1waqBvCjfr08y//kfr0xiNcsVocSYVQCoRxldahGtxqM=@googlegroups.com
X-Received: by 2002:a05:6122:1ac1:b0:559:ed61:4693 with SMTP id 71dfb90a1353d-55fed62beb4mr4186768e0c.10.1765858695939;
        Mon, 15 Dec 2025 20:18:15 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1765858695; cv=none;
        d=google.com; s=arc-20240605;
        b=B2ZHR2a4nnfvvMzOARakMJvT6r+PM4qaYQUQI0brNkLWiRF94d825lmrfsql64Q+Vr
         egN6ajdA4tsVBSef8mw4kzPKI0yNpQtdSYFex2TMrSYlXXTuMYbNPKNXGTUb3CRlur4b
         Sg7JgpvVqA6ESxirPF7D0204lrs81Dq7wHwL1+4jzWysRhFbRswG0fjRRcO6z7s8LXDA
         RgGNomY0igC5KmQCrNb3NkpVQsjf+y2gnXmnKMsDHyI2MqHT0ODPLvs0CHovz0HhSUOP
         5b6jlupAOAWOqDMt36//8VK/uBw1oOwmEDdeUX3+2R5BuubWDFLjeax9kBvRZF+mwg1f
         5m5w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=8DUjCNr/nxXg5R3wmw4ZM/MLoFfePhldzOpxojnv4JY=;
        fh=AM+LuqPVisaytRkLtJImMosBWvVtRjd6MTdcq7e4+V0=;
        b=L4/3HP49AhN53ZFXKJQE2MVMgBgAsGf7dKmpRhO9PtMFdnBRFN2cpT599kvWkiBGIe
         2VDLfia+WW5g4DdCYZAkqYJNyLaxvrwpO5xtJSkXxApJ6kJSUtKbCOjN+LnxfAKitavs
         LSTvsWvO4KRcLpidHiQoojjW4ApuKH4z1IBJUmF9ldQel5pGTa5/V/+4AWo4LCpL/Pv8
         cW5lDyt6quxeaebO2EnpynZlHTP+pbP2G1WcsEXC6KyXVgudPrcmIQNpUgHlw1DK4Po9
         d6pt1hj/9cNJXKEoOQY+/qJsaFTHxXvPUvCQgNzBwahyURJiW9zp8KAm5G7DWx4hTho1
         lhUA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=A5NjXvGD;
       spf=pass (google.com: domain of jasowang@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=jasowang@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.133.124])
        by gmr-mx.google.com with ESMTPS id 71dfb90a1353d-55fdc733b5fsi520978e0c.5.2025.12.15.20.18.15
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 15 Dec 2025 20:18:15 -0800 (PST)
Received-SPF: pass (google.com: domain of jasowang@redhat.com designates 170.10.133.124 as permitted sender) client-ip=170.10.133.124;
Received: from mail-pj1-f69.google.com (mail-pj1-f69.google.com
 [209.85.216.69]) by relay.mimecast.com with ESMTP with STARTTLS
 (version=TLSv1.3, cipher=TLS_AES_256_GCM_SHA384) id
 us-mta-392-p39_g4qMO7iYTH5PHQ9PVQ-1; Mon, 15 Dec 2025 23:18:14 -0500
X-MC-Unique: p39_g4qMO7iYTH5PHQ9PVQ-1
X-Mimecast-MFC-AGG-ID: p39_g4qMO7iYTH5PHQ9PVQ_1765858693
Received: by mail-pj1-f69.google.com with SMTP id 98e67ed59e1d1-34a8cdba421so5535556a91.2
        for <kasan-dev@googlegroups.com>; Mon, 15 Dec 2025 20:18:13 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCWrHUu7C8/lOyJ8EJqm9RocqWk9FcB1w9UiA2/v0MfSx9UvqQ06i/pi3pl+BuvtvUq9fPxpxqO3TDs=@googlegroups.com
X-Gm-Gg: AY/fxX59OfNjRqvB3YmzCZUsNLEiCMwGfCEmlUU6mErsJwVm6dAvcwBLc3y82eb3O6G
	uP9b4uvlifOezKjcR2ub5wUwaJlWZtvGVYRIMoxDGBYf6ottnlVrZm8sLHZ93hsyD1CWqXNQe1f
	TfA7Xq/LAuKlXnrvxUh3QfiteEh/DqAdc5LVrTHmYiHfcOAyqJA3hn5QaLCdp5ZA0Gxg==
X-Received: by 2002:a17:90b:2ccf:b0:340:f05a:3ec2 with SMTP id 98e67ed59e1d1-34abd81733amr14699610a91.17.1765858692989;
        Mon, 15 Dec 2025 20:18:12 -0800 (PST)
X-Received: by 2002:a17:90b:2ccf:b0:340:f05a:3ec2 with SMTP id
 98e67ed59e1d1-34abd81733amr14699535a91.17.1765858692536; Mon, 15 Dec 2025
 20:18:12 -0800 (PST)
MIME-Version: 1.0
References: <20251215113903.46555-1-bagasdotme@gmail.com> <20251215113903.46555-7-bagasdotme@gmail.com>
In-Reply-To: <20251215113903.46555-7-bagasdotme@gmail.com>
From: "'Jason Wang' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 16 Dec 2025 12:17:59 +0800
X-Gm-Features: AQt7F2q1idGMqOnPlq5afbA61NEyezJumJNhfdWiFdPMuPeC3DZ1U_cOOaqg6iI
Message-ID: <CACGkMEtJt7Df5kXWex8EoKdakdB8_xLjgCXQt5pUvk0dkGzVMA@mail.gmail.com>
Subject: Re: [PATCH 06/14] virtio: Describe @map and @vmap members in
 virtio_device struct
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
	Marco Elver <elver@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	"Michael S. Tsirkin" <mst@redhat.com>, Xuan Zhuo <xuanzhuo@linux.alibaba.com>, 
	=?UTF-8?Q?Eugenio_P=C3=A9rez?= <eperezma@redhat.com>, 
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
X-Mimecast-Spam-Score: 0
X-Mimecast-MFC-PROC-ID: isJmOfd6IaZeQ2zQib-cyKHlYvaJGWIpCDKZFEnsj7Y_1765858693
X-Mimecast-Originator: redhat.com
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: jasowang@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=A5NjXvGD;
       spf=pass (google.com: domain of jasowang@redhat.com designates
 170.10.133.124 as permitted sender) smtp.mailfrom=jasowang@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
X-Original-From: Jason Wang <jasowang@redhat.com>
Reply-To: Jason Wang <jasowang@redhat.com>
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

On Mon, Dec 15, 2025 at 7:39=E2=80=AFPM Bagas Sanjaya <bagasdotme@gmail.com=
> wrote:
>
> Sphinx reports kernel-doc warnings:
>
> WARNING: ./include/linux/virtio.h:181 struct member 'map' not described i=
n 'virtio_device'
> WARNING: ./include/linux/virtio.h:181 struct member 'vmap' not described =
in 'virtio_device'
>
> Describe these members.
>
> Fixes: bee8c7c24b7373 ("virtio: introduce map ops in virtio core")
> Signed-off-by: Bagas Sanjaya <bagasdotme@gmail.com>
> ---

Acked-by: Jason Wang <jasowang@redhat.com>

Thanks

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
ACGkMEtJt7Df5kXWex8EoKdakdB8_xLjgCXQt5pUvk0dkGzVMA%40mail.gmail.com.
