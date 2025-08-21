Return-Path: <kasan-dev+bncBC32535MUICBB7XYTXCQMGQEY3KTWSY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3d.google.com (mail-qv1-xf3d.google.com [IPv6:2607:f8b0:4864:20::f3d])
	by mail.lfdr.de (Postfix) with ESMTPS id C6894B3036B
	for <lists+kasan-dev@lfdr.de>; Thu, 21 Aug 2025 22:07:27 +0200 (CEST)
Received: by mail-qv1-xf3d.google.com with SMTP id 6a1803df08f44-70a88d99c1csf29019576d6.0
        for <lists+kasan-dev@lfdr.de>; Thu, 21 Aug 2025 13:07:27 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1755806846; cv=pass;
        d=google.com; s=arc-20240605;
        b=IFZBW8x6X/fCkZFRCC8LdDJTCeTJkanQTdBAlL75Tw8iK606WqEO1RH8jBJZB/EPxs
         pO5WXVtfhy+4NsayEHW9wtD3uZDWwfI+rtlzUaNz7GU+jBEXy00EPxVXzhcY/wAnH3ua
         83d6SRFuHR9vCS/zrwWBwIKFqxdXzQHjj+mDYaAttWKUf/haT4gadtPbcEng0NtBPFrk
         CRSgnlXZlcQ9T+Tca8CSXYE82Z5Ufksmv9cD2sYv21mOQ349Vvlw0+SB80rE1+oLqt97
         6sXU9zSnX5WAVEH/Uh5zMJs5Aqv7TECuHSMycSRDydrP0kMrCi8qD2QId0Y6uf2wG0Nk
         6BlA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=dlg6gV0J7Pi6Gu55Hw5SsxhXhA5hO5iUjTh3nYB2yQ8=;
        fh=RBHTH4+i3k4qjtJahl5zozt+nxcy57moX5ENo/v119g=;
        b=Xb6Chaf1zIVHLWIrGoe2bT3sALNlFC1pYvE4Cao2QmtWIWfT1sm+aY+sVj1F7W1eRP
         NvY+99xA0uSvE8XeYUmw9VOsshtR5tK6CYSPAIPo8oW2ocGLOPOSB1bfWgvHCNBeQmcZ
         FbUFpnlZrYF5YrMxGCUV5QZJZONAlNN8BmLgD0dR+3FKxuKQojvmNKXJqvifODvvE0h/
         /1xzCVcDNEfo1rEKbAGDKK9w4x9zS6E0NZbuu5KHH4E04oil0gsLOFc4WfOKTin59CQa
         c1uim8Kd3X6UGaN5WsOxPc/yO4cT73Lq70gtHBhvfgS/hOVLIIvKLdPRu5Cgbq8lFxID
         HiVQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=hJBsxZ1o;
       spf=pass (google.com: domain of dhildenb@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=dhildenb@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1755806846; x=1756411646; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=dlg6gV0J7Pi6Gu55Hw5SsxhXhA5hO5iUjTh3nYB2yQ8=;
        b=dILsesHRAMObwjvmO+mvh7LITFZmDonMfiCbN2rBR9c/CP9KnJwEyLAVqE9hRzQ87F
         tkKDaT93WtbPXT+uS5ITLbGobFdbdt8YtkhJ9czn32dB9s7r7S6ISTo0BU5APxO21+z3
         jZDC+iKTwxUVKlGIuaXLPkF/azOXkMEJNQa8GcjZYdnpILCLAocDAFecPcwWJErtQyVP
         Q6sLbeAyT/lgVExjts8/15jplNepZatlDCOPoX2rs6EDC2SyjEjFr9+XhdxTDHM9gNWQ
         PLM03jjnaP+0AE7bSOMR6hEGtlIsOT9H8rU4In2zMJ4cJ6c+QNgrDvzoP3Weis1F+ACz
         kyng==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1755806846; x=1756411646;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=dlg6gV0J7Pi6Gu55Hw5SsxhXhA5hO5iUjTh3nYB2yQ8=;
        b=pcU2xGNRC732KST1IVSY57UaAoSGtfYKmpZ01QoJZP9RBjA8v08fRCZiA8Bbz1gPDj
         1L3ENR7IERzkooJ5UV/ZQR3rIQIES/8gdRtfzE/PtynO7SujVc5MKZPXAj7KyOugYSqv
         rVf5cxsU6Wyi/yf2OhiIHtqbT0MigF8uWNAklB08ZF+WyRpdGBRDxvSWK1Iq6CA0AoNn
         5OAoqmzrgyebY9nY4NMlY3x3HQuQ1hBKJSYyVHaZGrpQRZiwf9/Cikn+UZQHankG2dJv
         KVWf+91FzFah+pq2Cg++VISmRyEEeYST6Py6GGJUqdfkQ+2/FRBMH+k0W8v7jpcEbsMz
         Ow9A==
X-Forwarded-Encrypted: i=2; AJvYcCUcMbO9eOVyBkcQrihuQylrB3Z85rcbZkLe0Bob9A2vb6mxw6d0iSpYmuujl93swYdEreXWmA==@lfdr.de
X-Gm-Message-State: AOJu0YzSal7Jh4F68MmkvUKDEXfWr+DVkHf1AfNQFJOSWQjWymMBSkbe
	pet1tJvmUpEBGODZSlyl5TVYzeiI5cjo4CXiddT0yZklQQvsBrzSlx9X
X-Google-Smtp-Source: AGHT+IEatX7iP+IEGtvvyx+XPZ9ILh/e5J8IIQx5oxMzKM5OfMcxIkE3BEjVba1dBDjngUIru1di4Q==
X-Received: by 2002:ad4:5764:0:b0:6fa:a4ed:cce5 with SMTP id 6a1803df08f44-70d971e4228mr8805836d6.44.1755806846320;
        Thu, 21 Aug 2025 13:07:26 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZf57y+wqlfrzgS/HuLv4QSTZmbYE3GyKN0fHODGK4WRpA==
Received: by 2002:a05:6214:2626:b0:707:1963:1433 with SMTP id
 6a1803df08f44-70d85cf9c02ls19706276d6.2.-pod-prod-01-us; Thu, 21 Aug 2025
 13:07:25 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWvUzNXGuTEhhvbN+7cSToMGmJBqaY8bkLcKGRpfNduSU70Ji6F30S+2bxqMTIt+QKxqI4vuxQDYCU=@googlegroups.com
X-Received: by 2002:a05:6122:8285:b0:53c:6d68:1cd5 with SMTP id 71dfb90a1353d-53c8a45b6e8mr231343e0c.15.1755806845282;
        Thu, 21 Aug 2025 13:07:25 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1755806845; cv=none;
        d=google.com; s=arc-20240605;
        b=JHW83zcBpwLx5FpqFBeJzsKVotZMYkNONdFDHmrjMZA03mj4eMdQs7KOpyGZ7SuJd5
         06z6+VyTZoraO+GlvsoGeE3BtTNDrqnKigd8eu2A6PfoE+Q2lcY96dara9GkOgMQ+UXZ
         8+yCKSi2KqEdDKYELa75LHkKQv8y9Dnb+gCgo0E0IW+Ltle/x8G2iZbXGHVtqKRgl5W7
         26IfmmfwbbvsPn6kZNGdJYOIW2DgdIzHXZF3DnKOuZ7RAA8wuGmZ3unp8ItpGp282qlX
         V2eBi7Hi9Z5BUmzJzADOp0DeE8t2c9y7MqlZpaZZzUgaz//UuFLmKt0D1G+Xg3SgmmTo
         pytQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=aOl+Pd7m6DQCTUATshUDhXjEbKNtUx8aQQ0CVjE/d9w=;
        fh=Cyw9hne9/OL3kJ4DdmgskZZrW2hd17gXGwlUYdqDILQ=;
        b=SqynkVilnNRpRPycSIKSJsuEUZtzY/DpC900kvB7PyINciYR7Av0nFYBL/2T0hwfqo
         Mel67u3EYZ5evU8O1KM6OPuyDTq2D5EMYCvFXivsDw6UERW7NaGM56DvYkNyGN+Y5zrr
         MoYXZNwxmXb8zTSQrcHQuNDb36ctq4G0FuaBiH2Vu34pQhEKkcdPP3mJ3O67j9onIPtE
         gvuwI7VYXlQO5V6Ii84or+ZDv886BTnb1Y/UVy+mHIpJ2rty/UdO2RaIFhdw5VKL+oCq
         C7PDKbRt/8mwC4eaqBtLKQoN6Ch88lvOGOjltzLV9vFHbp+RwHY4vd6qktqBLq+CFf3O
         0J/A==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=hJBsxZ1o;
       spf=pass (google.com: domain of dhildenb@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=dhildenb@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.129.124])
        by gmr-mx.google.com with ESMTPS id 71dfb90a1353d-53b2be22c8esi806039e0c.1.2025.08.21.13.07.25
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 21 Aug 2025 13:07:25 -0700 (PDT)
Received-SPF: pass (google.com: domain of dhildenb@redhat.com designates 170.10.129.124 as permitted sender) client-ip=170.10.129.124;
Received: from mail-wm1-f69.google.com (mail-wm1-f69.google.com
 [209.85.128.69]) by relay.mimecast.com with ESMTP with STARTTLS
 (version=TLSv1.3, cipher=TLS_AES_256_GCM_SHA384) id
 us-mta-589-lfg21zyLOImI5ic3D_BbzQ-1; Thu, 21 Aug 2025 16:07:23 -0400
X-MC-Unique: lfg21zyLOImI5ic3D_BbzQ-1
X-Mimecast-MFC-AGG-ID: lfg21zyLOImI5ic3D_BbzQ_1755806842
Received: by mail-wm1-f69.google.com with SMTP id 5b1f17b1804b1-45a1b0045a0so8433975e9.0
        for <kasan-dev@googlegroups.com>; Thu, 21 Aug 2025 13:07:22 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCXJnRv64oBchcnMKqm0tJclrtvwSjGaqV5MsdXULSvlf6jc+0VoVe/X0vAY1wMd9rmWSEEqVhNIrmc=@googlegroups.com
X-Gm-Gg: ASbGncsdoZmq8j0pP82NZwEdGbJdKIPHAt5oYBqHzEgMzC6UTNs4buJnRSWxvZ0QPoa
	NnPKBGHEjDptKYWXNbsa24ABEv1N15+mb8IGdkgLEqd1mrcNRa+BSxt+wBzihBGl4fKFRhjKVQM
	96TI0e9ki/FZPwuhFjI9UnkfpVLc3eCyIZH7SZmVUl4P6YYLKPG/NWMy1SD97QWal9vZp+P4jjw
	e8iMWgL+T/94uWlEWS93xV0dbE7n6w0PsI9LZQto+P2wahu/LAK+3MgOKdX1aylbNmCt6UQjRzN
	2reGxOKXrU5MvaKxydGpM1rPQQ3gbm6CUPrtJErHa+uDa1Xtd7BmhjlEVAxWLUXEvGrKz/rw/Qj
	525ZDrjPJbT8I+0DiAnRd4w==
X-Received: by 2002:a05:600c:1993:b0:456:e39:ec1a with SMTP id 5b1f17b1804b1-45b517ad4a9mr2412745e9.14.1755806841722;
        Thu, 21 Aug 2025 13:07:21 -0700 (PDT)
X-Received: by 2002:a05:600c:1993:b0:456:e39:ec1a with SMTP id 5b1f17b1804b1-45b517ad4a9mr2412295e9.14.1755806841198;
        Thu, 21 Aug 2025 13:07:21 -0700 (PDT)
Received: from localhost (p200300d82f26ba0008036ec5991806fd.dip0.t-ipconnect.de. [2003:d8:2f26:ba00:803:6ec5:9918:6fd])
        by smtp.gmail.com with UTF8SMTPSA id 5b1f17b1804b1-45b50dc00a8sm10960275e9.1.2025.08.21.13.07.19
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 21 Aug 2025 13:07:20 -0700 (PDT)
From: "'David Hildenbrand' via kasan-dev" <kasan-dev@googlegroups.com>
To: linux-kernel@vger.kernel.org
Cc: David Hildenbrand <david@redhat.com>,
	"Jason A. Donenfeld" <Jason@zx2c4.com>,
	Shuah Khan <shuah@kernel.org>,
	Alexander Potapenko <glider@google.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Brendan Jackman <jackmanb@google.com>,
	Christoph Lameter <cl@gentwo.org>,
	Dennis Zhou <dennis@kernel.org>,
	Dmitry Vyukov <dvyukov@google.com>,
	dri-devel@lists.freedesktop.org,
	intel-gfx@lists.freedesktop.org,
	iommu@lists.linux.dev,
	io-uring@vger.kernel.org,
	Jason Gunthorpe <jgg@nvidia.com>,
	Jens Axboe <axboe@kernel.dk>,
	Johannes Weiner <hannes@cmpxchg.org>,
	John Hubbard <jhubbard@nvidia.com>,
	kasan-dev@googlegroups.com,
	kvm@vger.kernel.org,
	"Liam R. Howlett" <Liam.Howlett@oracle.com>,
	Linus Torvalds <torvalds@linux-foundation.org>,
	linux-arm-kernel@axis.com,
	linux-arm-kernel@lists.infradead.org,
	linux-crypto@vger.kernel.org,
	linux-ide@vger.kernel.org,
	linux-kselftest@vger.kernel.org,
	linux-mips@vger.kernel.org,
	linux-mmc@vger.kernel.org,
	linux-mm@kvack.org,
	linux-riscv@lists.infradead.org,
	linux-s390@vger.kernel.org,
	linux-scsi@vger.kernel.org,
	Lorenzo Stoakes <lorenzo.stoakes@oracle.com>,
	Marco Elver <elver@google.com>,
	Marek Szyprowski <m.szyprowski@samsung.com>,
	Michal Hocko <mhocko@suse.com>,
	Mike Rapoport <rppt@kernel.org>,
	Muchun Song <muchun.song@linux.dev>,
	netdev@vger.kernel.org,
	Oscar Salvador <osalvador@suse.de>,
	Peter Xu <peterx@redhat.com>,
	Robin Murphy <robin.murphy@arm.com>,
	Suren Baghdasaryan <surenb@google.com>,
	Tejun Heo <tj@kernel.org>,
	virtualization@lists.linux.dev,
	Vlastimil Babka <vbabka@suse.cz>,
	wireguard@lists.zx2c4.com,
	x86@kernel.org,
	Zi Yan <ziy@nvidia.com>
Subject: [PATCH RFC 05/35] wireguard: selftests: remove CONFIG_SPARSEMEM_VMEMMAP=y from qemu kernel config
Date: Thu, 21 Aug 2025 22:06:31 +0200
Message-ID: <20250821200701.1329277-6-david@redhat.com>
X-Mailer: git-send-email 2.50.1
In-Reply-To: <20250821200701.1329277-1-david@redhat.com>
References: <20250821200701.1329277-1-david@redhat.com>
MIME-Version: 1.0
X-Mimecast-Spam-Score: 0
X-Mimecast-MFC-PROC-ID: ZzTAXZEHRavvdheB6wW-CdmDxZxVC_eeZOxIUOKuelg_1755806842
X-Mimecast-Originator: redhat.com
content-type: text/plain; charset="UTF-8"; x-default=true
X-Original-Sender: david@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=hJBsxZ1o;
       spf=pass (google.com: domain of dhildenb@redhat.com designates
 170.10.129.124 as permitted sender) smtp.mailfrom=dhildenb@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
X-Original-From: David Hildenbrand <david@redhat.com>
Reply-To: David Hildenbrand <david@redhat.com>
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

It's no longer user-selectable (and the default was already "y"), so
let's just drop it.

Cc: "Jason A. Donenfeld" <Jason@zx2c4.com>
Cc: Shuah Khan <shuah@kernel.org>
Signed-off-by: David Hildenbrand <david@redhat.com>
---
 tools/testing/selftests/wireguard/qemu/kernel.config | 1 -
 1 file changed, 1 deletion(-)

diff --git a/tools/testing/selftests/wireguard/qemu/kernel.config b/tools/testing/selftests/wireguard/qemu/kernel.config
index 0a5381717e9f4..1149289f4b30f 100644
--- a/tools/testing/selftests/wireguard/qemu/kernel.config
+++ b/tools/testing/selftests/wireguard/qemu/kernel.config
@@ -48,7 +48,6 @@ CONFIG_JUMP_LABEL=y
 CONFIG_FUTEX=y
 CONFIG_SHMEM=y
 CONFIG_SLUB=y
-CONFIG_SPARSEMEM_VMEMMAP=y
 CONFIG_SMP=y
 CONFIG_SCHED_SMT=y
 CONFIG_SCHED_MC=y
-- 
2.50.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250821200701.1329277-6-david%40redhat.com.
