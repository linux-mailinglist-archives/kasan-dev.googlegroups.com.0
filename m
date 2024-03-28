Return-Path: <kasan-dev+bncBCXO5E6EQQFBBKX6SWYAMGQETVENHAA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x3b.google.com (mail-oa1-x3b.google.com [IPv6:2001:4860:4864:20::3b])
	by mail.lfdr.de (Postfix) with ESMTPS id 783048901B9
	for <lists+kasan-dev@lfdr.de>; Thu, 28 Mar 2024 15:31:08 +0100 (CET)
Received: by mail-oa1-x3b.google.com with SMTP id 586e51a60fabf-229f74246b1sf969677fac.1
        for <lists+kasan-dev@lfdr.de>; Thu, 28 Mar 2024 07:31:08 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1711636267; cv=pass;
        d=google.com; s=arc-20160816;
        b=NGTw6IHuHORBgZAOgNgSCsbp7i+K9t/egwHsRak3tmzNfUDheLnlnwOKjuBOBn0rER
         XHTSp+IR6BsDBx2rCaRCqadZtuqLpMfODMMyZrhsBXFwSMuG7tc0wd8xgMmJ69QBwrDQ
         qFCSuXLsgGBbvkvFSnFp6vbJYxMoGR43bmHrkL1kTMYf3N+UY8ORmrUSR+EjHvy950lZ
         ov4WT03FoWjwqZnmgcj+gwxsdReNlZZ+h/ydstLJVnDxXgDHqskOi2vSjPnPeTGVINNa
         56VhYL7fbm5z0wbtscq8QOq/DXCcXVikWB5znh/0uBlqRHAE9bMaaUTBk8YyYfjQ/YaP
         BZ+Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=R1x9e4Ke0F9u8gLVLTgWoO9ote0z+xzTSWJ4hcvwHio=;
        fh=DNoXuniSjijMrYKJXy1JDetSnS2OI0ymMX0lIIDdQpA=;
        b=PCLd5PFby2c59UUXeri0VEKCXGR/Y5v571WQ6KRO+8dMuRDYDza5kk4lsQXbnljfwR
         di8zCOj9VqaZokxsTOIau4hsJjCzpzSnpuSVLNSrxWQmvDs36UvwnGmzQvT4zed5DOHI
         OKbHo3MRY7Z2FMgrHx54ZV2935KBPKbHtLDjZu9h8MABWEykernOS9LGjqM39KVs3PXx
         Z8Gu5KVi73wt9QspMFpteD8e54xm4Ul92lWFotU6UUhT6e3OplSNddMmaYO+4ttB6ZQs
         pJVOG/1TmwsaQYbTigmJ2+u0uLo7BAK/G7pKTmN/+EMiVP6eIN0tCfScRa2isR5v0snv
         C6Eg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=eWM+Qp30;
       spf=pass (google.com: domain of arnd@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=arnd@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1711636267; x=1712241067; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:cc:to:from
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=R1x9e4Ke0F9u8gLVLTgWoO9ote0z+xzTSWJ4hcvwHio=;
        b=xVdNM+/wZsdi7eXp/bbegSVioK5OvbW7VZLLBKCfgDiaVv3iWRhRaC+J1QWAYtXlFf
         Q+MyjDV7BuI4ACWLIhDJiDxELwqZyzxpxXkNOOTAVApAcvAnts2qI8yCZgvXLKl+QMpJ
         sKesBlSVs3eWCNrNFUI8op5dszb6z/NHIsOG0UnmuM7NXVWHdvCuV+y1nBZVNjT2+0bx
         h0q9WLr3z7IEajED60FLwai/d6vtVKUVRnR1hz6JICGT8EAOeUvPaIypqB+JIel67gJ5
         uBMCz0N0lxUnv1xfnnhQSXpN3PesO7cAL/uEvLa65vL14aslEPzjmgOMmmvdebxPoojA
         AFuQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1711636267; x=1712241067;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=R1x9e4Ke0F9u8gLVLTgWoO9ote0z+xzTSWJ4hcvwHio=;
        b=BzYDlRxjfBX60VMZa/pfoY6+jCXskiirGmnIFKlaK2QaEE/9JLAF92J5qzNIVeB1C6
         simrM4ah6TErwNQ+axaCLNsWGoPiUIcFlEAyuB88ePt6PthjbCOxEZwED36vc2YxaDjT
         MtqKejHJOylXfaNHbHM6CFZtnI0vDaNUHSjAWhHXjejF4LKFUBBy9HpEiLiTs+QIsUfG
         8tGrl5NKl2pX1eJ9b7v9nMAc7oEMiYkIrXlSpCzlIIHbxGNa3VreYbhETUbH16XLsFOB
         1cy4vzoP95TEJWUrctGVItyElUWpRST0c7QRK7h8W4tturN86IyJrGypQyINYgqOBvEM
         1ScQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWGazLUnLbSwTogsP9uoEtNyr+5AJ/u4vMAelM1PHl6ilAD35Wz0+ZIraJAszStLYBW5gHNBDtEXbAKA/788XjESUL3zLveUA==
X-Gm-Message-State: AOJu0Yw8PwBOynrI2RIuqQCwcZm/AqShFKeJpMbT9kJpsNwoE6M3MzcE
	3RUHMOnh5earGE3YlBpJYjBnNKn9SOw7ilM0Zy7Lsaq4Yq+LJASB
X-Google-Smtp-Source: AGHT+IHrJQL1jcKDMMJXzWZ9UgmRvtzgAUw53xcWcjVgRE58f26aZHS29zd2C91MY78T5n05T+MM/w==
X-Received: by 2002:a05:6870:5d99:b0:21e:df8b:5280 with SMTP id fu25-20020a0568705d9900b0021edf8b5280mr3640856oab.27.1711636266995;
        Thu, 28 Mar 2024 07:31:06 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6871:430d:b0:229:eefd:98d5 with SMTP id
 lu13-20020a056871430d00b00229eefd98d5ls1374309oab.2.-pod-prod-07-us; Thu, 28
 Mar 2024 07:31:05 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUjxapLUFoewpBr+s3MpNSWMNzuVFEWkQCVsN6ZyNKQfRhl1b7h3PqBaEUx7XUvkle183Oz12bjF/j2WFKaqX/l1iIvvt+gQQsAeg==
X-Received: by 2002:a05:6870:d88f:b0:229:f31d:8be with SMTP id oe15-20020a056870d88f00b00229f31d08bemr3253444oac.53.1711636265481;
        Thu, 28 Mar 2024 07:31:05 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1711636265; cv=none;
        d=google.com; s=arc-20160816;
        b=gMrPe2j5aNLSZ8YE4ak0ToACnwxrsYe0IQs/AlLEKSz56HeWV/fGRjzuNwxlwJHexC
         19q408CuKRXKD6iJRbrH8hq/FY1OPLHPAnRe0KFbcuncCLlfoCJ+SvTZ0ZhMs9RoyAdF
         B9LawEtuZzpZU/99FdYKYN+mTNPW2HsjKcILzWKdhSvROt+SYbr+cdPajzvwBKTgnMpb
         jNNRO+aPrLHz+IpaF8msBVrnoz4p0tW3ZoA+49iQRWgFcGEM0hca60qq0je0P4Rf67GQ
         mq4/AfO77AY2V5zdPZF7xboiuPQ5p9aL2vuZIYhX4XM2E4E5ZWa9ZJO0xS4cyuytcswg
         gh+A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=5L6DqwuUaLYAo8kwwzqjy/3qUZ37Q2bwADOKOPODaN0=;
        fh=kQ+Mqdxvap/AhJCVXu1vvMkcEfgMk69oBD4zZoVcD88=;
        b=xLWM9KfrZlM/SBzpPQL/zV3kp7rZS88km0TOMKip3tJX0MdQCg/ve2so2SE+UtG8IS
         9h9C47rPKI/edT/QB+5FFg9i7AdMMrvvua0jzxdVRKdHed+iKE11MrvUbfii4sMgqXIo
         Y5i82TvJfk/zM+n7HTsi8hMObcwO2hunPmxRL6djkRn9oGFRLULaQw+PNyAaDUQjtEXh
         jjhmNp7NAOUv2/wCl1ur2Cp3vXhsruAx0OhqqampDAPHPA7e1kRp6A6u51yxTQEAyif6
         uGvgikyZRyBU36VzaBoLMDskyVCPeCEqSDdjn8bFYHMyo8/GKDoKaNQCafivaykTBA+0
         EvPA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=eWM+Qp30;
       spf=pass (google.com: domain of arnd@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=arnd@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [139.178.84.217])
        by gmr-mx.google.com with ESMTPS id q15-20020a056830018f00b006e6f4709684si130727ota.5.2024.03.28.07.31.05
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 28 Mar 2024 07:31:05 -0700 (PDT)
Received-SPF: pass (google.com: domain of arnd@kernel.org designates 139.178.84.217 as permitted sender) client-ip=139.178.84.217;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by dfw.source.kernel.org (Postfix) with ESMTP id EB17E6171F;
	Thu, 28 Mar 2024 14:31:04 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id D7141C433C7;
	Thu, 28 Mar 2024 14:30:56 +0000 (UTC)
From: Arnd Bergmann <arnd@kernel.org>
To: linux-kernel@vger.kernel.org
Cc: Arnd Bergmann <arnd@arndb.de>,
	Ilya Dryomov <idryomov@gmail.com>,
	Dongsheng Yang <dongsheng.yang@easystack.cn>,
	Jens Axboe <axboe@kernel.dk>,
	Jason Gunthorpe <jgg@ziepe.ca>,
	Leon Romanovsky <leon@kernel.org>,
	Alasdair Kergon <agk@redhat.com>,
	Mike Snitzer <snitzer@kernel.org>,
	Mikulas Patocka <mpatocka@redhat.com>,
	dm-devel@lists.linux.dev,
	Saeed Mahameed <saeedm@nvidia.com>,
	"David S. Miller" <davem@davemloft.net>,
	Eric Dumazet <edumazet@google.com>,
	Jakub Kicinski <kuba@kernel.org>,
	Paolo Abeni <pabeni@redhat.com>,
	Xiubo Li <xiubli@redhat.com>,
	Jeff Layton <jlayton@kernel.org>,
	Ryusuke Konishi <konishi.ryusuke@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	David Ahern <dsahern@kernel.org>,
	Masahiro Yamada <masahiroy@kernel.org>,
	Nathan Chancellor <nathan@kernel.org>,
	Nicolas Schier <nicolas@fjasle.eu>,
	Nick Desaulniers <ndesaulniers@google.com>,
	Bill Wendling <morbo@google.com>,
	Justin Stitt <justinstitt@google.com>,
	Kees Cook <keescook@chromium.org>,
	"Gustavo A. R. Silva" <gustavoars@kernel.org>,
	Tariq Toukan <tariqt@nvidia.com>,
	ceph-devel@vger.kernel.org,
	linux-block@vger.kernel.org,
	linux-rdma@vger.kernel.org,
	netdev@vger.kernel.org,
	linux-nilfs@vger.kernel.org,
	kasan-dev@googlegroups.com,
	linux-kbuild@vger.kernel.org,
	llvm@lists.linux.dev
Subject: [PATCH 0/9] address remaining -Wtautological-constant-out-of-range-compare
Date: Thu, 28 Mar 2024 15:30:38 +0100
Message-Id: <20240328143051.1069575-1-arnd@kernel.org>
X-Mailer: git-send-email 2.39.2
MIME-Version: 1.0
X-Original-Sender: arnd@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=eWM+Qp30;       spf=pass
 (google.com: domain of arnd@kernel.org designates 139.178.84.217 as permitted
 sender) smtp.mailfrom=arnd@kernel.org;       dmarc=pass (p=NONE sp=NONE
 dis=NONE) header.from=kernel.org
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

From: Arnd Bergmann <arnd@arndb.de>

The warning option was introduced a few years ago but left disabled
by default. All of the actual bugs that this has found have been
fixed in the meantime, and this series should address the remaining
false-positives, as tested on arm/arm64/x86 randconfigs as well as
allmodconfig builds for all architectures supported by clang.

Please apply the patches individually to subsystem maintainer trees.

      Arnd

Arnd Bergmann (9):
  dm integrity: fix out-of-range warning
  libceph: avoid clang out-of-range warning
  rbd: avoid out-of-range warning
  kcov: avoid clang out-of-range warning
  ipv4: tcp_output: avoid warning about NET_ADD_STATS
  nilfs2: fix out-of-range warning
  infiniband: uverbs: avoid out-of-range warnings
  mlx5: stop warning for 64KB pages
  kbuild: enable tautological-constant-out-of-range-compare

 drivers/block/rbd.c                                    | 2 +-
 drivers/infiniband/core/uverbs_ioctl.c                 | 4 ++--
 drivers/md/dm-integrity.c                              | 2 +-
 drivers/net/ethernet/mellanox/mlx5/core/en/xsk/setup.c | 6 ++++--
 fs/ceph/snap.c                                         | 2 +-
 fs/nilfs2/ioctl.c                                      | 2 +-
 kernel/kcov.c                                          | 3 ++-
 net/ceph/osdmap.c                                      | 4 ++--
 net/ipv4/tcp_output.c                                  | 2 +-
 scripts/Makefile.extrawarn                             | 1 -
 10 files changed, 15 insertions(+), 13 deletions(-)

-- 
2.39.2

Cc: Ilya Dryomov <idryomov@gmail.com>
Cc: Dongsheng Yang <dongsheng.yang@easystack.cn>
Cc: Jens Axboe <axboe@kernel.dk>
Cc: Jason Gunthorpe <jgg@ziepe.ca>
Cc: Leon Romanovsky <leon@kernel.org>
Cc: Alasdair Kergon <agk@redhat.com>
Cc: Mike Snitzer <snitzer@kernel.org>
Cc: Mikulas Patocka <mpatocka@redhat.com>
Cc: dm-devel@lists.linux.dev
Cc: Saeed Mahameed <saeedm@nvidia.com>
Cc: "David S. Miller" <davem@davemloft.net>
Cc: Eric Dumazet <edumazet@google.com>
Cc: Jakub Kicinski <kuba@kernel.org>
Cc: Paolo Abeni <pabeni@redhat.com>
Cc: Xiubo Li <xiubli@redhat.com>
Cc: Jeff Layton <jlayton@kernel.org>
Cc: Ryusuke Konishi <konishi.ryusuke@gmail.com>
Cc: Dmitry Vyukov <dvyukov@google.com>
Cc: Andrey Konovalov <andreyknvl@gmail.com>
Cc: David Ahern <dsahern@kernel.org>
Cc: Masahiro Yamada <masahiroy@kernel.org>
Cc: Nathan Chancellor <nathan@kernel.org>
Cc: Nicolas Schier <nicolas@fjasle.eu>
Cc: Nick Desaulniers <ndesaulniers@google.com>
Cc: Bill Wendling <morbo@google.com>
Cc: Justin Stitt <justinstitt@google.com>
Cc: Kees Cook <keescook@chromium.org>
Cc: "Gustavo A. R. Silva" <gustavoars@kernel.org>
Cc: Arnd Bergmann <arnd@arndb.de>
Cc: Tariq Toukan <tariqt@nvidia.com>
Cc: ceph-devel@vger.kernel.org
Cc: linux-block@vger.kernel.org
Cc: linux-kernel@vger.kernel.org
Cc: linux-rdma@vger.kernel.org
Cc: netdev@vger.kernel.org
Cc: linux-nilfs@vger.kernel.org
Cc: kasan-dev@googlegroups.com
Cc: linux-kbuild@vger.kernel.org
Cc: llvm@lists.linux.dev

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240328143051.1069575-1-arnd%40kernel.org.
