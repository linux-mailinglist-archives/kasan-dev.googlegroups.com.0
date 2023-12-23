Return-Path: <kasan-dev+bncBC4LXIPCY4NRBUFATKWAMGQEDBYVZGY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x139.google.com (mail-il1-x139.google.com [IPv6:2607:f8b0:4864:20::139])
	by mail.lfdr.de (Postfix) with ESMTPS id 5933881D2F6
	for <lists+kasan-dev@lfdr.de>; Sat, 23 Dec 2023 08:46:26 +0100 (CET)
Received: by mail-il1-x139.google.com with SMTP id e9e14a558f8ab-35fe758285asf489275ab.0
        for <lists+kasan-dev@lfdr.de>; Fri, 22 Dec 2023 23:46:26 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1703317585; cv=pass;
        d=google.com; s=arc-20160816;
        b=X0ySX4aVSc7OrIPmFtXgIHfrhkfMnqcUjX+0iLCo5g7Fx6hvG2jQAIqo+c94CrfZUy
         clanZM9OGsrNGUGsweANF1i48NDa8L55SKNu9srhqoYGIFLsg1udge7jsHd0etfNwQZ8
         LHh56oro27oXu2sDfZeulQEBw9HSD22x5nK8d4XU0KfPfjJMCdocPhlXDdtVSr3xVbvU
         yT/JfdYFnNrYI/HbpmxyBHlJA+BNTAe7L1nUjBgnS0cif5sujFmyIzmY7tDVTM1SkAxW
         qVAqUTntayMS372MZA4TZGWbgAITUDJTnfT97AlJ/aT3ZUC2piNRbw3K+heJnA1RmXQl
         vJYw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :user-agent:message-id:subject:cc:to:from:date:mime-version:sender
         :dkim-signature;
        bh=tNsSUmo6WFcg2CXJYC6SDq3cAtV5hPXnl5lne9nj24A=;
        fh=lyuFaeLf56RAGHgsXzrQNJuoXxorN/pEPSuh+AGG9+E=;
        b=z+kL2vvWT1BFXSeG+T3buuPfzsjvyzQIY8AuwVZ3kRu9m730gdI1rgNIPKEgJyz16E
         CraXOzMBeLPSbWzpDMrLOpHZKfRZvBTJqcgzjGB3BD7LTzpb6InK4N/shEMF+YIgFT6/
         n/r0GZkpyetTmD77BgJCBzxLwucq+gFcbgy96PrJ6JmZFOGGeJAS29bQghhx/B6q0zfu
         hb0sJMNc0gCnhPa1Dx9bclXko7k5nxu/owZ+sjuSaXZ/Z3b4gJI7qQ0qyOv20PQnkIYv
         omaBBi8x9KsxzYUuHffX9zPcIUoO0JBjKYDL2DYK6zXk52oZAL/xuiQ0+RUPQSNKudlH
         3DCg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=gmW4ttez;
       spf=pass (google.com: domain of lkp@intel.com designates 198.175.65.9 as permitted sender) smtp.mailfrom=lkp@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1703317585; x=1703922385; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :x-original-authentication-results:x-original-sender:user-agent
         :message-id:subject:cc:to:from:date:mime-version:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=tNsSUmo6WFcg2CXJYC6SDq3cAtV5hPXnl5lne9nj24A=;
        b=HYvjtf9L78L9iOMLtTlehsTnM11ZRHW+Tkg2fPICsJ72syl6kJS4uUkGGswa9TIv/a
         ZbEQcZKwmPVLthy5Kvm9Jnmy/Yw/RuKonDUfZmw6Rmdi631t+Lp1vnf+pVuSTfJsDTVK
         ob+omBLSxeo+IgoHUvQh3I4/8U11zgIjzm3q4dOUgckHiTYLpi6JqR8x0x00wBFYVHXC
         eH1V4ZI4cK/EsLKHKvUxl1AeWwQ2I2ui/8IyWjP257K6toQkoADlsKuLLxUQh3QWByaJ
         CNr5KorpCtqevsALhHCV/CZxjVYu067hjk5hs31ZhCU0SdUqC0DVN+uk18dbRMeSYhJp
         CVqw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1703317585; x=1703922385;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :content-transfer-encoding:x-original-authentication-results
         :x-original-sender:user-agent:message-id:subject:cc:to:from:date
         :x-beenthere:mime-version:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=tNsSUmo6WFcg2CXJYC6SDq3cAtV5hPXnl5lne9nj24A=;
        b=fKmxnuzrdyqQQE26mwGBpF53eQXJke2GNHtd23OqX6q22q4J+H5YDIFDqM5NFO3VK/
         hf249C5v22cnyPtczVp2g/kzACIRn9+HC3sYhKFgqhydtqCBQInXVEt7A+K3UPvFCGRH
         r0DbtdCBhf4q8zYoy1GZ++nihrbdiGQMv5F6AoDIqDcCOOyGss6XvPzli+vnrd5lSB+U
         TN+n/HQYA8L4CAEj8paGJy7CcpOQWW9D2zboC+ohrCUj9gu53/KYt7InL8Gc+St9Qvff
         lcfXKR3ZXwrVZ2aglkoMn3DY1RHPZguIU3835HsWmgpDrrZpJpB3knfJflMaBWw6ldBz
         jYaA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YzuOEPnS22n+i0TimmqygPf4Q1vhrtSjtz0XzpwiuxPjORWmcz3
	xdfnnbVRU6H9i6QPMKm4YnA=
X-Google-Smtp-Source: AGHT+IHZ7gb5iFGiCPkR4bdCWQRLfAetsNxyt9fisy28ACTXVIp6JnLC7u2jQ0rCGE97HIirvhEfMQ==
X-Received: by 2002:a05:6e02:1a6c:b0:35f:c36c:5155 with SMTP id w12-20020a056e021a6c00b0035fc36c5155mr251777ilv.17.1703317584543;
        Fri, 22 Dec 2023 23:46:24 -0800 (PST)
MIME-Version: 1.0
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a92:ab02:0:b0:35f:684d:727e with SMTP id v2-20020a92ab02000000b0035f684d727els2348929ilh.1.-pod-prod-04-us;
 Fri, 22 Dec 2023 23:46:23 -0800 (PST)
X-Received: by 2002:a05:6e02:3202:b0:35f:ea6b:cecd with SMTP id cd2-20020a056e02320200b0035fea6bcecdmr1302341ilb.12.1703317583671;
        Fri, 22 Dec 2023 23:46:23 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1703317583; cv=none;
        d=google.com; s=arc-20160816;
        b=Z7NlqAAo/Ki4ByzVk6ERfZFwI5zQbTQbBnTvCb+tAv65YwbPYsfCs646Y8HNDlU647
         eVNbrxhSCtCVqkDgHYXr4R/OO4TRoqjdoscqj1BYAmq5yFJDpMLg8u/nxog7KWcBy+jV
         R3xRWORUHHukgm99ZZ+cTYgidSg8URtbrWS3MFlMtbxr8eREyvV04XYsAR63LhARISbW
         EeR2Y7Wuwshv+O8E4MPx3fEStJdUW2ddlUFWCox+8PoBKs0eS1e4o84QozT8vxBaDOIz
         MBJGYPzINqbkdGTZlDWXUNZ2D5clwcW3/17JgQtEaJGxfoYQjmXIxghwgPAvuCXysH2d
         PvSQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:message-id:subject:cc:to:from:date:dkim-signature;
        bh=EDvy6oXKCjnqzxDi1oP4zZE4i6yx9pvPGGgbt3e7v6Y=;
        fh=lyuFaeLf56RAGHgsXzrQNJuoXxorN/pEPSuh+AGG9+E=;
        b=RvYdbm92cbiZwoe/gTB+RIhBPsBvvq3yDTNrh34VR6wtX4Km45klLLF/7hfBDxikLq
         PBrVbFq/TQ5/kGHKsMkE8ScHUcEYr41LZD30zyeU7jlXloiOfQzGRrqEQBXSyt75MM7q
         9Jbi45UUT3N+iJuY+WqdYX3rgvrUdn8XJ7Z0b4//NneWbWyDPgNJYWUT6VghaTnJ08xN
         oErp9F7Lzl5C3r1EZTtNRpeH7jveEe5UcIZMqHFgPzvWEmjT8rud58nPS0cPUw6Bw4xR
         kQan7UX5VazkfoczBbTNE3V5lFUcvlNLyugn3wHsjvOMBQMGlr1RMpEVCuJw1+pdo0dh
         zbuw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=gmW4ttez;
       spf=pass (google.com: domain of lkp@intel.com designates 198.175.65.9 as permitted sender) smtp.mailfrom=lkp@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
Received: from mgamail.intel.com (mgamail.intel.com. [198.175.65.9])
        by gmr-mx.google.com with ESMTPS id n4-20020a056e0208e400b0035c8d7c3820si469142ilt.2.2023.12.22.23.46.22
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 22 Dec 2023 23:46:23 -0800 (PST)
Received-SPF: pass (google.com: domain of lkp@intel.com designates 198.175.65.9 as permitted sender) client-ip=198.175.65.9;
X-IronPort-AV: E=McAfee;i="6600,9927,10932"; a="14868164"
X-IronPort-AV: E=Sophos;i="6.04,298,1695711600"; 
   d="scan'208";a="14868164"
Received: from orsmga007.jf.intel.com ([10.7.209.58])
  by orvoesa101.jf.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 22 Dec 2023 23:45:57 -0800
X-ExtLoop1: 1
X-IronPort-AV: E=McAfee;i="6600,9927,10932"; a="770554474"
X-IronPort-AV: E=Sophos;i="6.04,298,1695711600"; 
   d="scan'208";a="770554474"
Received: from lkp-server02.sh.intel.com (HELO b07ab15da5fe) ([10.239.97.151])
  by orsmga007.jf.intel.com with ESMTP; 22 Dec 2023 23:45:50 -0800
Received: from kbuild by b07ab15da5fe with local (Exim 4.96)
	(envelope-from <lkp@intel.com>)
	id 1rGwhc-000AQv-1K;
	Sat, 23 Dec 2023 07:45:46 +0000
Date: Sat, 23 Dec 2023 15:44:46 +0800
From: kernel test robot <lkp@intel.com>
To: Andrew Morton <akpm@linux-foundation.org>
Cc: Linux Memory Management List <linux-mm@kvack.org>,
 alsa-devel@alsa-project.org, amd-gfx@lists.freedesktop.org,
 ceph-devel@vger.kernel.org, dmaengine@vger.kernel.org,
 dri-devel@lists.freedesktop.org, freedreno@lists.freedesktop.org,
 intel-wired-lan@lists.osuosl.org, kasan-dev@googlegroups.com,
 kunit-dev@googlegroups.com, linux-arm-msm@vger.kernel.org,
 linux-atm-general@lists.sourceforge.net, linux-bcachefs@vger.kernel.org,
 linux-cifs@vger.kernel.org, linux-csky@vger.kernel.org,
 linux-fsdevel@vger.kernel.org, linux-hwmon@vger.kernel.org,
 linux-ide@vger.kernel.org, linux-kselftest@vger.kernel.org,
 linux-scsi@vger.kernel.org, mpi3mr-linuxdrv.pdl@broadcom.com
Subject: [linux-next:master] BUILD REGRESSION
 39676dfe52331dba909c617f213fdb21015c8d10
Message-ID: <202312231534.UWFO81PH-lkp@intel.com>
User-Agent: s-nail v14.9.24
X-Original-Sender: lkp@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=gmW4ttez;       spf=pass
 (google.com: domain of lkp@intel.com designates 198.175.65.9 as permitted
 sender) smtp.mailfrom=lkp@intel.com;       dmarc=pass (p=NONE sp=NONE
 dis=NONE) header.from=intel.com
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
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

tree/branch: https://git.kernel.org/pub/scm/linux/kernel/git/next/linux-nex=
t.git master
branch HEAD: 39676dfe52331dba909c617f213fdb21015c8d10  Add linux-next speci=
fic files for 20231222

Error/Warning reports:

https://lore.kernel.org/oe-kbuild-all/202312222155.w90Evz26-lkp@intel.com
https://lore.kernel.org/oe-kbuild-all/202312230634.3AIMQ3OP-lkp@intel.com
https://lore.kernel.org/oe-kbuild-all/202312230642.EBF6kiYY-lkp@intel.com
https://lore.kernel.org/oe-kbuild-all/202312231042.LGJY7ydP-lkp@intel.com
https://lore.kernel.org/oe-kbuild-all/202312231258.L3C56jBw-lkp@intel.com

Error/Warning: (recently discovered and may have been fixed)

drivers/dma/xilinx/xdma.c:555: warning: Function parameter or member 'dst_a=
ddr' not described in 'xdma_fill_descs'
drivers/dma/xilinx/xdma.c:555: warning: Function parameter or member 'fille=
d_descs_num' not described in 'xdma_fill_descs'
drivers/dma/xilinx/xdma.c:555: warning: Function parameter or member 'size'=
 not described in 'xdma_fill_descs'
drivers/dma/xilinx/xdma.c:555: warning: Function parameter or member 'src_a=
ddr' not described in 'xdma_fill_descs'
drivers/dma/xilinx/xdma.c:555: warning: Function parameter or member 'sw_de=
sc' not described in 'xdma_fill_descs'
drivers/dma/xilinx/xdma.c:555: warning: Function parameter or struct member=
 'dst_addr' not described in 'xdma_fill_descs'
drivers/dma/xilinx/xdma.c:555: warning: Function parameter or struct member=
 'filled_descs_num' not described in 'xdma_fill_descs'
drivers/dma/xilinx/xdma.c:555: warning: Function parameter or struct member=
 'size' not described in 'xdma_fill_descs'
drivers/dma/xilinx/xdma.c:555: warning: Function parameter or struct member=
 'src_addr' not described in 'xdma_fill_descs'
drivers/dma/xilinx/xdma.c:555: warning: Function parameter or struct member=
 'sw_desc' not described in 'xdma_fill_descs'
drivers/dma/xilinx/xdma.c:729:1: warning: no previous prototype for 'xdma_p=
rep_interleaved_dma' [-Wmissing-prototypes]
drivers/dma/xilinx/xdma.c:729:1: warning: no previous prototype for functio=
n 'xdma_prep_interleaved_dma' [-Wmissing-prototypes]
drivers/dma/xilinx/xdma.c:757:68: warning: operator '?:' has lower preceden=
ce than '+'; '+' will be evaluated first [-Wparentheses]
drivers/dma/xilinx/xdma.c:894:3: warning: variable 'desc' is uninitialized =
when used here [-Wuninitialized]
lib/aolib.h:366:16: error: variable 'key2' has initializer but incomplete t=
ype
lib/aolib.h:366:34: error: storage size of 'key2' isn't known
lib/aolib.h:369:46: error: invalid use of undefined type 'struct tcp_ao_add=
'
lib/aolib.h:382:16: error: variable 'tmp' has initializer but incomplete ty=
pe
lib/aolib.h:382:27: error: storage size of 'tmp' isn't known
lib/aolib.h:390:43: error: 'TCP_AO_ADD_KEY' undeclared (first use in this f=
unction)
lib/aolib.h:406:16: error: variable 'ao2' has initializer but incomplete ty=
pe
lib/aolib.h:406:32: error: storage size of 'ao2' isn't known
lib/aolib.h:418:16: error: variable 'ao' has initializer but incomplete typ=
e
lib/aolib.h:418:32: error: storage size of 'ao' isn't known
lib/kconfig.c:47:16: error: variable 'tmp' has initializer but incomplete t=
ype
lib/kconfig.c:47:27: error: storage size of 'tmp' isn't known
lib/kconfig.c:64:41: error: 'TCP_AO_ADD_KEY' undeclared (first use in this =
function)
lib/repair.c:115:6: error: conflicting types for 'test_ao_checkpoint'; have=
 'void(int,  struct tcp_ao_repair *)'
lib/repair.c:117:31: error: invalid application of 'sizeof' to incomplete t=
ype 'struct tcp_ao_repair'
lib/repair.c:122:39: error: 'TCP_AO_REPAIR' undeclared (first use in this f=
unction); did you mean 'TCP_REPAIR'?
lib/repair.c:222:6: error: conflicting types for 'test_ao_restore'; have 'v=
oid(int,  struct tcp_ao_repair *)'
lib/sock.c:136:5: error: conflicting types for 'test_prepare_key_sockaddr';=
 have 'int(struct tcp_ao_add *, const char *, void *, size_t,  _Bool,  _Boo=
l,  uint8_t,  uint8_t,  uint8_t,  uint8_t,  uint8_t,  uint8_t,  uint8_t,  c=
onst char *)' {aka 'int(struct tcp_ao_add *, const char *, void *, long uns=
igned int,  _Bool,  _Bool,  unsigned char,  unsigned char,  unsigned char, =
 unsigned char,  unsigned char,  unsigned char,  unsigned char,  const char=
 *)'}
lib/sock.c:142:30: error: invalid application of 'sizeof' to incomplete typ=
e 'struct tcp_ao_add'
lib/sock.c:144:11: error: invalid use of undefined type 'struct tcp_ao_add'
lib/sock.c:161:26: error: 'TCP_AO_MAXKEYLEN' undeclared (first use in this =
function); did you mean 'TCP_MD5SIG_MAXKEYLEN'?
lib/sock.c:167:16: error: variable 'tmp' has initializer but incomplete typ=
e
lib/sock.c:167:34: error: storage size of 'tmp' isn't known
lib/sock.c:174:43: error: 'TCP_AO_GET_KEYS' undeclared (first use in this f=
unction)
lib/sock.c:180:5: error: conflicting types for 'test_get_one_ao'; have 'int=
(int,  struct tcp_ao_getsockopt *, void *, size_t,  uint8_t,  uint8_t,  uin=
t8_t)' {aka 'int(int,  struct tcp_ao_getsockopt *, void *, long unsigned in=
t,  unsigned char,  unsigned char,  unsigned char)'}
lib/sock.c:199:14: error: invalid use of undefined type 'struct tcp_ao_gets=
ockopt'
lib/sock.c:203:5: error: conflicting types for 'test_get_ao_info'; have 'in=
t(int,  struct tcp_ao_info_opt *)'
lib/sock.c:205:30: error: invalid application of 'sizeof' to incomplete typ=
e 'struct tcp_ao_info_opt'
lib/sock.c:207:12: error: invalid use of undefined type 'struct tcp_ao_info=
_opt'
lib/sock.c:209:41: error: 'TCP_AO_INFO' undeclared (first use in this funct=
ion); did you mean 'TCP_CC_INFO'?
lib/sock.c:216:5: error: conflicting types for 'test_set_ao_info'; have 'in=
t(int,  struct tcp_ao_info_opt *)'
lib/sock.c:227:5: error: conflicting types for 'test_cmp_getsockopt_setsock=
opt'; have 'int(const struct tcp_ao_add *, const struct tcp_ao_getsockopt *=
)'
lib/sock.c:233:38: error: invalid use of undefined type 'const struct tcp_a=
o_add'
lib/sock.c:240:14: error: invalid use of undefined type 'const struct tcp_a=
o_getsockopt'
lib/sock.c:299:5: error: conflicting types for 'test_cmp_getsockopt_setsock=
opt_ao'; have 'int(const struct tcp_ao_info_opt *, const struct tcp_ao_info=
_opt *)'
lib/sock.c:303:14: error: invalid use of undefined type 'const struct tcp_a=
o_info_opt'
lib/sock.c:337:39: error: invalid application of 'sizeof' to incomplete typ=
e 'struct tcp_ao_getsockopt'
lib/sock.c:338:16: error: variable 'info' has initializer but incomplete ty=
pe
lib/sock.c:338:32: error: storage size of 'info' isn't known
powerpc64-linux-ld: warning: orphan section `.bss..Lubsan_data794' from `ke=
rnel/ptrace.o' being placed in section `.bss..Lubsan_data794'

Unverified Error/Warning (likely false positive, please contact us if inter=
ested):

drivers/dma/xilinx/xdma.c:894 xdma_channel_isr() error: potentially derefer=
encing uninitialized 'desc'.
fs/smb/client/file.c:2744:(.text+0x95ae): relocation truncated to fit: R_CK=
CORE_PCREL_IMM16BY4 against `__jump_table'
include/linux/pagemap.h:231:(.text+0x968c): relocation truncated to fit: R_=
CKCORE_PCREL_IMM16BY4 against `__jump_table'
include/linux/syscalls.h:257:9: internal compiler error: in change_address_=
1, at emit-rtl.cc:2287
sound/pci/hda/cs35l41_hda_property.c:176:27: warning: unused variable 'cs_g=
piod' [-Wunused-variable]
sound/pci/hda/cs35l41_hda_property.c:177:28: warning: unused variable 'spi'=
 [-Wunused-variable]
{standard input}:21016: Warning: overflow in branch to .L4838; converted in=
to longer instruction sequence
{standard input}:26527: Error: pcrel too far
{standard input}:6990: Warning: overflow in branch to .L1661; converted int=
o longer instruction sequence

Error/Warning ids grouped by kconfigs:

gcc_recent_errors
|-- alpha-allyesconfig
|   |-- drivers-gpu-drm-amd-amdgpu-..-display-dc-core-dc_state.c:warning:Ex=
cess-function-parameter-context-description-in-dc_state_rem_all_planes_for_=
stream
|   |-- drivers-gpu-drm-amd-amdgpu-..-display-dc-core-dc_state.c:warning:Fu=
nction-parameter-or-struct-member-state-not-described-in-dc_state_rem_all_p=
lanes_for_stream
|   |-- drivers-gpu-drm-amd-amdgpu-..-display-dc-dc_dmub_srv.c:warning:Func=
tion-parameter-or-struct-member-context-not-described-in-populate_subvp_cmd=
_drr_info
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-drv-=
not-described-in-kunit_device_register_with_driver
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-name=
-not-described-in-kunit_device_register
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-name=
-not-described-in-kunit_device_register_with_driver
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-name=
-not-described-in-kunit_driver_create
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-test=
-not-described-in-kunit_device_register
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-test=
-not-described-in-kunit_device_register_with_driver
|   `-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-test=
-not-described-in-kunit_driver_create
|-- arc-allmodconfig
|   |-- drivers-gpu-drm-amd-amdgpu-..-display-dc-core-dc_state.c:warning:Ex=
cess-function-parameter-context-description-in-dc_state_rem_all_planes_for_=
stream
|   |-- drivers-gpu-drm-amd-amdgpu-..-display-dc-core-dc_state.c:warning:Fu=
nction-parameter-or-struct-member-state-not-described-in-dc_state_rem_all_p=
lanes_for_stream
|   |-- drivers-gpu-drm-amd-amdgpu-..-display-dc-dc_dmub_srv.c:warning:Func=
tion-parameter-or-struct-member-context-not-described-in-populate_subvp_cmd=
_drr_info
|   |-- drivers-gpu-drm-msm-disp-dpu1-dpu_encoder.c:warning:Excess-struct-m=
ember-debugfs_root-description-in-dpu_encoder_virt
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-drv-=
not-described-in-kunit_device_register_with_driver
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-name=
-not-described-in-kunit_device_register
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-name=
-not-described-in-kunit_device_register_with_driver
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-name=
-not-described-in-kunit_driver_create
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-test=
-not-described-in-kunit_device_register
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-test=
-not-described-in-kunit_device_register_with_driver
|   `-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-test=
-not-described-in-kunit_driver_create
|-- arc-allyesconfig
|   |-- drivers-gpu-drm-amd-amdgpu-..-display-dc-core-dc_state.c:warning:Ex=
cess-function-parameter-context-description-in-dc_state_rem_all_planes_for_=
stream
|   |-- drivers-gpu-drm-amd-amdgpu-..-display-dc-core-dc_state.c:warning:Fu=
nction-parameter-or-struct-member-state-not-described-in-dc_state_rem_all_p=
lanes_for_stream
|   |-- drivers-gpu-drm-amd-amdgpu-..-display-dc-dc_dmub_srv.c:warning:Func=
tion-parameter-or-struct-member-context-not-described-in-populate_subvp_cmd=
_drr_info
|   |-- drivers-gpu-drm-msm-disp-dpu1-dpu_encoder.c:warning:Excess-struct-m=
ember-debugfs_root-description-in-dpu_encoder_virt
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-drv-=
not-described-in-kunit_device_register_with_driver
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-name=
-not-described-in-kunit_device_register
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-name=
-not-described-in-kunit_device_register_with_driver
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-name=
-not-described-in-kunit_driver_create
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-test=
-not-described-in-kunit_device_register
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-test=
-not-described-in-kunit_device_register_with_driver
|   `-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-test=
-not-described-in-kunit_driver_create
|-- arc-randconfig-002-20231222
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-member-dst_=
addr-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-member-fill=
ed_descs_num-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-member-size=
-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-member-src_=
addr-not-described-in-xdma_fill_descs
|   `-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-member-sw_d=
esc-not-described-in-xdma_fill_descs
|-- arc-randconfig-r122-20231222
|   |-- fs-bcachefs-btree_iter.c:sparse:sparse:incompatible-types-in-compar=
ison-expression-(different-address-spaces):
|   |-- fs-bcachefs-btree_locking.c:sparse:sparse:incompatible-types-in-com=
parison-expression-(different-address-spaces):
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-drv-=
not-described-in-kunit_device_register_with_driver
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-name=
-not-described-in-kunit_device_register
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-name=
-not-described-in-kunit_device_register_with_driver
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-name=
-not-described-in-kunit_driver_create
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-test=
-not-described-in-kunit_device_register
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-test=
-not-described-in-kunit_device_register_with_driver
|   `-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-test=
-not-described-in-kunit_driver_create
|-- arm-allmodconfig
|   |-- drivers-gpu-drm-amd-amdgpu-..-display-dc-core-dc_state.c:warning:Ex=
cess-function-parameter-context-description-in-dc_state_rem_all_planes_for_=
stream
|   |-- drivers-gpu-drm-amd-amdgpu-..-display-dc-core-dc_state.c:warning:Fu=
nction-parameter-or-struct-member-state-not-described-in-dc_state_rem_all_p=
lanes_for_stream
|   |-- drivers-gpu-drm-amd-amdgpu-..-display-dc-dc_dmub_srv.c:warning:Func=
tion-parameter-or-struct-member-context-not-described-in-populate_subvp_cmd=
_drr_info
|   |-- drivers-gpu-drm-msm-disp-dpu1-dpu_encoder.c:warning:Excess-struct-m=
ember-debugfs_root-description-in-dpu_encoder_virt
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-drv-=
not-described-in-kunit_device_register_with_driver
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-name=
-not-described-in-kunit_device_register
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-name=
-not-described-in-kunit_device_register_with_driver
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-name=
-not-described-in-kunit_driver_create
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-test=
-not-described-in-kunit_device_register
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-test=
-not-described-in-kunit_device_register_with_driver
|   `-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-test=
-not-described-in-kunit_driver_create
|-- arm-allyesconfig
|   |-- drivers-gpu-drm-amd-amdgpu-..-display-dc-core-dc_state.c:warning:Ex=
cess-function-parameter-context-description-in-dc_state_rem_all_planes_for_=
stream
|   |-- drivers-gpu-drm-amd-amdgpu-..-display-dc-core-dc_state.c:warning:Fu=
nction-parameter-or-struct-member-state-not-described-in-dc_state_rem_all_p=
lanes_for_stream
|   |-- drivers-gpu-drm-amd-amdgpu-..-display-dc-dc_dmub_srv.c:warning:Func=
tion-parameter-or-struct-member-context-not-described-in-populate_subvp_cmd=
_drr_info
|   |-- drivers-gpu-drm-msm-disp-dpu1-dpu_encoder.c:warning:Excess-struct-m=
ember-debugfs_root-description-in-dpu_encoder_virt
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-drv-=
not-described-in-kunit_device_register_with_driver
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-name=
-not-described-in-kunit_device_register
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-name=
-not-described-in-kunit_device_register_with_driver
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-name=
-not-described-in-kunit_driver_create
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-test=
-not-described-in-kunit_device_register
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-test=
-not-described-in-kunit_device_register_with_driver
|   `-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-test=
-not-described-in-kunit_driver_create
|-- arm-randconfig-001-20231222
|   |-- WARNING:modpost:missing-MODULE_DESCRIPTION()-in-lib-zlib_inflate-zl=
ib_inflate.o
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-drv-=
not-described-in-kunit_device_register_with_driver
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-name=
-not-described-in-kunit_device_register
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-name=
-not-described-in-kunit_device_register_with_driver
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-name=
-not-described-in-kunit_driver_create
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-test=
-not-described-in-kunit_device_register
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-test=
-not-described-in-kunit_device_register_with_driver
|   `-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-test=
-not-described-in-kunit_driver_create
|-- arm-randconfig-002-20231222
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-drv-=
not-described-in-kunit_device_register_with_driver
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-name=
-not-described-in-kunit_device_register
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-name=
-not-described-in-kunit_device_register_with_driver
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-name=
-not-described-in-kunit_driver_create
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-test=
-not-described-in-kunit_device_register
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-test=
-not-described-in-kunit_device_register_with_driver
|   `-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-test=
-not-described-in-kunit_driver_create
|-- arm-randconfig-003-20231222
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-drv-=
not-described-in-kunit_device_register_with_driver
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-name=
-not-described-in-kunit_device_register
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-name=
-not-described-in-kunit_device_register_with_driver
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-name=
-not-described-in-kunit_driver_create
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-test=
-not-described-in-kunit_device_register
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-test=
-not-described-in-kunit_device_register_with_driver
|   `-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-test=
-not-described-in-kunit_driver_create
|-- arm-randconfig-004-20231222
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-drv-=
not-described-in-kunit_device_register_with_driver
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-name=
-not-described-in-kunit_device_register
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-name=
-not-described-in-kunit_device_register_with_driver
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-name=
-not-described-in-kunit_driver_create
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-test=
-not-described-in-kunit_device_register
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-test=
-not-described-in-kunit_device_register_with_driver
|   `-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-test=
-not-described-in-kunit_driver_create
|-- arm64-defconfig
|   |-- drivers-gpu-drm-imagination-pvr_mmu.c:warning:Excess-struct-member-=
l0_free_tables-description-in-pvr_mmu_op_context
|   |-- drivers-gpu-drm-imagination-pvr_mmu.c:warning:Excess-struct-member-=
l0_prealloc_tables-description-in-pvr_mmu_op_context
|   |-- drivers-gpu-drm-imagination-pvr_mmu.c:warning:Excess-struct-member-=
l1_free_tables-description-in-pvr_mmu_op_context
|   |-- drivers-gpu-drm-imagination-pvr_mmu.c:warning:Excess-struct-member-=
l1_prealloc_tables-description-in-pvr_mmu_op_context
|   |-- drivers-gpu-drm-imagination-pvr_mmu.c:warning:Excess-struct-member-=
pvr_dev-description-in-pvr_mmu_backing_page
|   |-- drivers-gpu-drm-imagination-pvr_mmu.c:warning:Excess-struct-member-=
sgt-description-in-pvr_mmu_op_context
|   |-- drivers-gpu-drm-imagination-pvr_mmu.c:warning:Excess-struct-member-=
sgt_offset-description-in-pvr_mmu_op_context
|   `-- drivers-gpu-drm-msm-disp-dpu1-dpu_encoder.c:warning:Excess-struct-m=
ember-debugfs_root-description-in-dpu_encoder_virt
|-- arm64-randconfig-002-20231222
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-drv-=
not-described-in-kunit_device_register_with_driver
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-name=
-not-described-in-kunit_device_register
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-name=
-not-described-in-kunit_device_register_with_driver
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-name=
-not-described-in-kunit_driver_create
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-test=
-not-described-in-kunit_device_register
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-test=
-not-described-in-kunit_device_register_with_driver
|   `-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-test=
-not-described-in-kunit_driver_create
|-- arm64-randconfig-003-20231222
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-drv-=
not-described-in-kunit_device_register_with_driver
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-name=
-not-described-in-kunit_device_register
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-name=
-not-described-in-kunit_device_register_with_driver
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-name=
-not-described-in-kunit_driver_create
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-test=
-not-described-in-kunit_device_register
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-test=
-not-described-in-kunit_device_register_with_driver
|   `-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-test=
-not-described-in-kunit_driver_create
|-- arm64-randconfig-r061-20231222
|   |-- drivers-gpu-drm-msm-disp-dpu1-dpu_encoder.c:warning:Excess-struct-m=
ember-debugfs_root-description-in-dpu_encoder_virt
|   |-- drivers-net-ethernet-intel-ice-ice_base.c:error:storage-size-of-des=
c-isn-t-known
|   |-- drivers-net-ethernet-intel-ice-ice_base.c:error:variable-desc-has-i=
nitializer-but-incomplete-type
|   |-- drivers-net-ethernet-intel-ice-ice_base.c:warning:unused-variable-d=
esc
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-drv-=
not-described-in-kunit_device_register_with_driver
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-name=
-not-described-in-kunit_device_register
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-name=
-not-described-in-kunit_device_register_with_driver
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-name=
-not-described-in-kunit_driver_create
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-test=
-not-described-in-kunit_device_register
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-test=
-not-described-in-kunit_device_register_with_driver
|   `-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-test=
-not-described-in-kunit_driver_create
|-- arm64-randconfig-r063-20231222
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-drv-=
not-described-in-kunit_device_register_with_driver
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-name=
-not-described-in-kunit_device_register
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-name=
-not-described-in-kunit_device_register_with_driver
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-name=
-not-described-in-kunit_driver_create
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-test=
-not-described-in-kunit_device_register
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-test=
-not-described-in-kunit_device_register_with_driver
|   `-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-test=
-not-described-in-kunit_driver_create
|-- csky-allmodconfig
|   |-- drivers-gpu-drm-amd-amdgpu-..-display-dc-core-dc_state.c:warning:Ex=
cess-function-parameter-context-description-in-dc_state_rem_all_planes_for_=
stream
|   |-- drivers-gpu-drm-amd-amdgpu-..-display-dc-core-dc_state.c:warning:Fu=
nction-parameter-or-struct-member-state-not-described-in-dc_state_rem_all_p=
lanes_for_stream
|   |-- drivers-gpu-drm-amd-amdgpu-..-display-dc-dc_dmub_srv.c:warning:Func=
tion-parameter-or-struct-member-context-not-described-in-populate_subvp_cmd=
_drr_info
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-drv-=
not-described-in-kunit_device_register_with_driver
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-name=
-not-described-in-kunit_device_register
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-name=
-not-described-in-kunit_device_register_with_driver
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-name=
-not-described-in-kunit_driver_create
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-test=
-not-described-in-kunit_device_register
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-test=
-not-described-in-kunit_device_register_with_driver
|   `-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-test=
-not-described-in-kunit_driver_create
|-- csky-allyesconfig
|   |-- drivers-gpu-drm-amd-amdgpu-..-display-dc-core-dc_state.c:warning:Ex=
cess-function-parameter-context-description-in-dc_state_rem_all_planes_for_=
stream
|   |-- drivers-gpu-drm-amd-amdgpu-..-display-dc-core-dc_state.c:warning:Fu=
nction-parameter-or-struct-member-state-not-described-in-dc_state_rem_all_p=
lanes_for_stream
|   |-- drivers-gpu-drm-amd-amdgpu-..-display-dc-dc_dmub_srv.c:warning:Func=
tion-parameter-or-struct-member-context-not-described-in-populate_subvp_cmd=
_drr_info
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-drv-=
not-described-in-kunit_device_register_with_driver
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-name=
-not-described-in-kunit_device_register
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-name=
-not-described-in-kunit_device_register_with_driver
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-name=
-not-described-in-kunit_driver_create
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-test=
-not-described-in-kunit_device_register
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-test=
-not-described-in-kunit_device_register_with_driver
|   `-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-test=
-not-described-in-kunit_driver_create
|-- csky-buildonly-randconfig-r004-20230509
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-memb=
er-dst_addr-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-memb=
er-filled_descs_num-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-memb=
er-size-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-memb=
er-src_addr-not-described-in-xdma_fill_descs
|   |-- drivers-dma-xilinx-xdma.c:warning:Function-parameter-or-struct-memb=
er-sw_desc-not-described-in-xdma_fill_descs
|   `-- drivers-dma-xilinx-xdma.c:warning:no-previous-prototype-for-xdma_pr=
ep_interleaved_dma
|-- csky-randconfig-001-20231222
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-drv-=
not-described-in-kunit_device_register_with_driver
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-name=
-not-described-in-kunit_device_register
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-name=
-not-described-in-kunit_device_register_with_driver
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-name=
-not-described-in-kunit_driver_create
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-test=
-not-described-in-kunit_device_register
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-test=
-not-described-in-kunit_device_register_with_driver
|   `-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-test=
-not-described-in-kunit_driver_create
|-- csky-randconfig-r023-20220124
|   |-- fs-smb-client-file.c:(.text):relocation-truncated-to-fit:R_CKCORE_P=
CREL_IMM16BY4-against-__jump_table
|   `-- include-linux-pagemap.h:(.text):relocation-truncated-to-fit:R_CKCOR=
E_PCREL_IMM16BY4-against-__jump_table
|-- csky-randconfig-r111-20231222
|   |-- arch-csky-kernel-vdso-vgettimeofday.c:sparse:sparse:function-__vdso=
_clock_gettime-with-external-linkage-has-definition
|   |-- fs-bcachefs-btree_iter.c:sparse:sparse:incompatible-types-in-compar=
ison-expression-(different-address-spaces):
|   |-- fs-bcachefs-btree_locking.c:sparse:sparse:incompatible-types-in-com=
parison-expression-(different-address-spaces):
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-drv-=
not-described-in-kunit_device_register_with_driver
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-name=
-not-described-in-kunit_device_register
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-name=
-not-described-in-kunit_device_register_with_driver
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-name=
-not-described-in-kunit_driver_create
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-test=
-not-described-in-kunit_device_register
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-test=
-not-described-in-kunit_device_register_with_driver
|   `-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-test=
-not-described-in-kunit_driver_create
|-- i386-buildonly-randconfig-002-20231222
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-drv-=
not-described-in-kunit_device_register_with_driver
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-name=
-not-described-in-kunit_device_register
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-name=
-not-described-in-kunit_device_register_with_driver
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-name=
-not-described-in-kunit_driver_create
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-test=
-not-described-in-kunit_device_register
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-test=
-not-described-in-kunit_device_register_with_driver
|   `-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-test=
-not-described-in-kunit_driver_create
|-- i386-buildonly-randconfig-006-20231222
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-drv-=
not-described-in-kunit_device_register_with_driver
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-name=
-not-described-in-kunit_device_register
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-name=
-not-described-in-kunit_device_register_with_driver
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-name=
-not-described-in-kunit_driver_create
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-test=
-not-described-in-kunit_device_register
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-test=
-not-described-in-kunit_device_register_with_driver
|   `-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-test=
-not-described-in-kunit_driver_create
|-- i386-randconfig-001-20231222
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-drv-=
not-described-in-kunit_device_register_with_driver
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-name=
-not-described-in-kunit_device_register
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-name=
-not-described-in-kunit_device_register_with_driver
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-name=
-not-described-in-kunit_driver_create
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-test=
-not-described-in-kunit_device_register
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-test=
-not-described-in-kunit_device_register_with_driver
|   `-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-test=
-not-described-in-kunit_driver_create
|-- i386-randconfig-002-20231222
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-drv-=
not-described-in-kunit_device_register_with_driver
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-name=
-not-described-in-kunit_device_register
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-name=
-not-described-in-kunit_device_register_with_driver
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-name=
-not-described-in-kunit_driver_create
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-test=
-not-described-in-kunit_device_register
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-test=
-not-described-in-kunit_device_register_with_driver
|   `-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-test=
-not-described-in-kunit_driver_create
|-- i386-randconfig-004-20231222
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-drv-=
not-described-in-kunit_device_register_with_driver
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-name=
-not-described-in-kunit_device_register
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-name=
-not-described-in-kunit_device_register_with_driver
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-name=
-not-described-in-kunit_driver_create
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-test=
-not-described-in-kunit_device_register
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-test=
-not-described-in-kunit_device_register_with_driver
|   `-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-test=
-not-described-in-kunit_driver_create
|-- i386-randconfig-005-20231222
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-drv-=
not-described-in-kunit_device_register_with_driver
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-name=
-not-described-in-kunit_device_register
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-name=
-not-described-in-kunit_device_register_with_driver
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-name=
-not-described-in-kunit_driver_create
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-test=
-not-described-in-kunit_device_register
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-test=
-not-described-in-kunit_device_register_with_driver
|   `-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-test=
-not-described-in-kunit_driver_create
|-- i386-randconfig-006-20231222
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-drv-=
not-described-in-kunit_device_register_with_driver
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-name=
-not-described-in-kunit_device_register
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-name=
-not-described-in-kunit_device_register_with_driver
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-name=
-not-described-in-kunit_driver_create
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-test=
-not-described-in-kunit_device_register
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-test=
-not-described-in-kunit_device_register_with_driver
|   `-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-test=
-not-described-in-kunit_driver_create
|-- i386-randconfig-051-20231222
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-drv-=
not-described-in-kunit_device_register_with_driver
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-name=
-not-described-in-kunit_device_register
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-name=
-not-described-in-kunit_device_register_with_driver
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-name=
-not-described-in-kunit_driver_create
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-test=
-not-described-in-kunit_device_register
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-test=
-not-described-in-kunit_device_register_with_driver
|   `-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-test=
-not-described-in-kunit_driver_create
|-- i386-randconfig-052-20231222
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-drv-=
not-described-in-kunit_device_register_with_driver
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-name=
-not-described-in-kunit_device_register
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-name=
-not-described-in-kunit_device_register_with_driver
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-name=
-not-described-in-kunit_driver_create
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-test=
-not-described-in-kunit_device_register
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-test=
-not-described-in-kunit_device_register_with_driver
|   `-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-test=
-not-described-in-kunit_driver_create
|-- i386-randconfig-054-20231222
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-drv-=
not-described-in-kunit_device_register_with_driver
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-name=
-not-described-in-kunit_device_register
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-name=
-not-described-in-kunit_device_register_with_driver
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-name=
-not-described-in-kunit_driver_create
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-test=
-not-described-in-kunit_device_register
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-test=
-not-described-in-kunit_device_register_with_driver
|   `-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-test=
-not-described-in-kunit_driver_create
|-- i386-randconfig-061-20231222
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-drv-=
not-described-in-kunit_device_register_with_driver
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-name=
-not-described-in-kunit_device_register
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-name=
-not-described-in-kunit_device_register_with_driver
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-name=
-not-described-in-kunit_driver_create
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-test=
-not-described-in-kunit_device_register
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-test=
-not-described-in-kunit_device_register_with_driver
|   `-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-test=
-not-described-in-kunit_driver_create
|-- i386-randconfig-141-20231222
|   |-- drivers-ata-ata_piix.c-piix_init_sata_map()-error:buffer-overflow-m=
ap
|   |-- fs-ceph-addr.c-writepages_finish()-error:page-dereferencing-possibl=
e-ERR_PTR()
|   |-- lib-kunit-device.c-kunit_device_register_with_driver()-warn:passing=
-zero-to-ERR_CAST
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-drv-=
not-described-in-kunit_device_register_with_driver
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-name=
-not-described-in-kunit_device_register
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-name=
-not-described-in-kunit_device_register_with_driver
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-name=
-not-described-in-kunit_driver_create
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-test=
-not-described-in-kunit_device_register
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-test=
-not-described-in-kunit_device_register_with_driver
|   `-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-test=
-not-described-in-kunit_driver_create
|-- i386-randconfig-r121-20231222
|   `-- drivers-hwmon-max31827.c:sparse:sparse:dubious:x-y
|-- loongarch-allmodconfig
|   |-- drivers-gpu-drm-amd-amdgpu-..-display-dc-core-dc_state.c:warning:Ex=
cess-function-parameter-context-description-in-dc_state_rem_all_planes_for_=
stream
|   |-- drivers-gpu-drm-amd-amdgpu-..-display-dc-core-dc_state.c:warning:Fu=
nction-parameter-or-struct-member-state-not-described-in-dc_state_rem_all_p=
lanes_for_stream
|   |-- drivers-gpu-drm-amd-amdgpu-..-display-dc-dc_dmub_srv.c:warning:Func=
tion-parameter-or-struct-member-context-not-described-in-populate_subvp_cmd=
_drr_info
|   |-- drivers-gpu-drm-amd-amdgpu-..-display-dc-hwss-dcn35-dcn35_hwseq.c:w=
arning:This-comment-starts-with-but-isn-t-a-kernel-doc-comment.-Refer-Docum=
entation-doc-guide-kernel-doc.rst
|   |-- drivers-gpu-drm-msm-disp-dpu1-dpu_encoder.c:warning:Excess-struct-m=
ember-debugfs_root-description-in-dpu_encoder_virt
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-drv-=
not-described-in-kunit_device_register_with_driver
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-name=
-not-described-in-kunit_device_register
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-name=
-not-described-in-kunit_device_register_with_driver
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-name=
-not-described-in-kunit_driver_create
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-test=
-not-described-in-kunit_device_register
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-test=
-not-described-in-kunit_device_register_with_driver
|   `-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-test=
-not-described-in-kunit_driver_create
|-- loongarch-defconfig
|   |-- drivers-gpu-drm-amd-amdgpu-..-display-dc-core-dc_state.c:warning:Ex=
cess-function-parameter-context-description-in-dc_state_rem_all_planes_for_=
stream
|   |-- drivers-gpu-drm-amd-amdgpu-..-display-dc-core-dc_state.c:warning:Fu=
nction-parameter-or-struct-member-state-not-described-in-dc_state_rem_all_p=
lanes_for_stream
|   |-- drivers-gpu-drm-amd-amdgpu-..-display-dc-dc_dmub_srv.c:warning:Func=
tion-parameter-or-struct-member-context-not-described-in-populate_subvp_cmd=
_drr_info
|   `-- drivers-gpu-drm-amd-amdgpu-..-display-dc-hwss-dcn35-dcn35_hwseq.c:w=
arning:This-comment-starts-with-but-isn-t-a-kernel-doc-comment.-Refer-Docum=
entation-doc-guide-kernel-doc.rst
|-- loongarch-loongson3_defconfig
|   |-- drivers-gpu-drm-amd-amdgpu-..-display-dc-core-dc_state.c:warning:Ex=
cess-function-parameter-context-description-in-dc_state_rem_all_planes_for_=
stream
|   |-- drivers-gpu-drm-amd-amdgpu-..-display-dc-core-dc_state.c:warning:Fu=
nction-parameter-or-struct-member-state-not-described-in-dc_state_rem_all_p=
lanes_for_stream
|   |-- drivers-gpu-drm-amd-amdgpu-..-display-dc-dc_dmub_srv.c:warning:Func=
tion-parameter-or-struct-member-context-not-described-in-populate_subvp_cmd=
_drr_info
|   `-- drivers-gpu-drm-amd-amdgpu-..-display-dc-hwss-dcn35-dcn35_hwseq.c:w=
arning:This-comment-starts-with-but-isn-t-a-kernel-doc-comment.-Refer-Docum=
entation-doc-guide-kernel-doc.rst
|-- loongarch-randconfig-001-20231222
|   |-- drivers-gpu-drm-amd-amdgpu-..-display-dc-core-dc_state.c:warning:Ex=
cess-function-parameter-context-description-in-dc_state_rem_all_planes_for_=
stream
|   |-- drivers-gpu-drm-amd-amdgpu-..-display-dc-core-dc_state.c:warning:Fu=
nction-parameter-or-struct-member-state-not-described-in-dc_state_rem_all_p=
lanes_for_stream
|   |-- drivers-gpu-drm-amd-amdgpu-..-display-dc-dc_dmub_srv.c:warning:Func=
tion-parameter-or-struct-member-context-not-described-in-populate_subvp_cmd=
_drr_info
|   `-- drivers-gpu-drm-amd-amdgpu-..-display-dc-hwss-dcn35-dcn35_hwseq.c:w=
arning:This-comment-starts-with-but-isn-t-a-kernel-doc-comment.-Refer-Docum=
entation-doc-guide-kernel-doc.rst
|-- loongarch-randconfig-002-20231222
|   |-- drivers-gpu-drm-amd-amdgpu-..-display-dc-core-dc_state.c:warning:Ex=
cess-function-parameter-context-description-in-dc_state_rem_all_planes_for_=
stream
|   |-- drivers-gpu-drm-amd-amdgpu-..-display-dc-core-dc_state.c:warning:Fu=
nction-parameter-or-struct-member-state-not-described-in-dc_state_rem_all_p=
lanes_for_stream
|   |-- drivers-gpu-drm-amd-amdgpu-..-display-dc-dc_dmub_srv.c:warning:Func=
tion-parameter-or-struct-member-context-not-described-in-populate_subvp_cmd=
_drr_info
|   |-- drivers-gpu-drm-amd-amdgpu-..-display-dc-hwss-dcn35-dcn35_hwseq.c:w=
arning:This-comment-starts-with-but-isn-t-a-kernel-doc-comment.-Refer-Docum=
entation-doc-guide-kernel-doc.rst
|   `-- drivers-gpu-drm-msm-disp-dpu1-dpu_encoder.c:warning:Excess-struct-m=
ember-debugfs_root-description-in-dpu_encoder_virt
|-- loongarch-randconfig-r131-20231222
|   |-- drivers-hwmon-max31827.c:sparse:sparse:dubious:x-y
|   |-- sound-pci-hda-cs35l41_hda_property.c:warning:unused-variable-cs_gpi=
od
|   `-- sound-pci-hda-cs35l41_hda_property.c:warning:unused-variable-spi
|-- m68k-allmodconfig
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-drv-=
not-described-in-kunit_device_register_with_driver
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-name=
-not-described-in-kunit_device_register
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-name=
-not-described-in-kunit_device_register_with_driver
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-name=
-not-described-in-kunit_driver_create
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-test=
-not-described-in-kunit_device_register
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-test=
-not-described-in-kunit_device_register_with_driver
|   `-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-test=
-not-described-in-kunit_driver_create
|-- m68k-allyesconfig
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-drv-=
not-described-in-kunit_device_register_with_driver
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-name=
-not-described-in-kunit_device_register
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-name=
-not-described-in-kunit_device_register_with_driver
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-name=
-not-described-in-kunit_driver_create
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-test=
-not-described-in-kunit_device_register
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-test=
-not-described-in-kunit_device_register_with_driver
|   `-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-test=
-not-described-in-kunit_driver_create
|-- m68k-defconfig
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-drv-=
not-described-in-kunit_device_register_with_driver
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-name=
-not-described-in-kunit_device_register
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-name=
-not-described-in-kunit_device_register_with_driver
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-name=
-not-described-in-kunit_driver_create
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-test=
-not-described-in-kunit_device_register
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-test=
-not-described-in-kunit_device_register_with_driver
|   `-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-test=
-not-described-in-kunit_driver_create
|-- microblaze-allmodconfig
|   |-- drivers-gpu-drm-amd-amdgpu-..-display-dc-core-dc_state.c:warning:Ex=
cess-function-parameter-context-description-in-dc_state_rem_all_planes_for_=
stream
|   |-- drivers-gpu-drm-amd-amdgpu-..-display-dc-core-dc_state.c:warning:Fu=
nction-parameter-or-struct-member-state-not-described-in-dc_state_rem_all_p=
lanes_for_stream
|   |-- drivers-gpu-drm-amd-amdgpu-..-display-dc-dc_dmub_srv.c:warning:Func=
tion-parameter-or-struct-member-context-not-described-in-populate_subvp_cmd=
_drr_info
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-drv-=
not-described-in-kunit_device_register_with_driver
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-name=
-not-described-in-kunit_device_register
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-name=
-not-described-in-kunit_device_register_with_driver
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-name=
-not-described-in-kunit_driver_create
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-test=
-not-described-in-kunit_device_register
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-test=
-not-described-in-kunit_device_register_with_driver
|   `-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-test=
-not-described-in-kunit_driver_create
|-- microblaze-allyesconfig
|   |-- drivers-gpu-drm-amd-amdgpu-..-display-dc-core-dc_state.c:warning:Ex=
cess-function-parameter-context-description-in-dc_state_rem_all_planes_for_=
stream
|   |-- drivers-gpu-drm-amd-amdgpu-..-display-dc-core-dc_state.c:warning:Fu=
nction-parameter-or-struct-member-state-not-described-in-dc_state_rem_all_p=
lanes_for_stream
|   |-- drivers-gpu-drm-amd-amdgpu-..-display-dc-dc_dmub_srv.c:warning:Func=
tion-parameter-or-struct-member-context-not-described-in-populate_subvp_cmd=
_drr_info
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-drv-=
not-described-in-kunit_device_register_with_driver
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-name=
-not-described-in-kunit_device_register
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-name=
-not-described-in-kunit_device_register_with_driver
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-name=
-not-described-in-kunit_driver_create
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-test=
-not-described-in-kunit_device_register
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-test=
-not-described-in-kunit_device_register_with_driver
|   `-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-test=
-not-described-in-kunit_driver_create
|-- mips-allyesconfig
|   |-- drivers-gpu-drm-amd-amdgpu-..-display-dc-core-dc_state.c:warning:Ex=
cess-function-parameter-context-description-in-dc_state_rem_all_planes_for_=
stream
|   |-- drivers-gpu-drm-amd-amdgpu-..-display-dc-core-dc_state.c:warning:Fu=
nction-parameter-or-struct-member-state-not-described-in-dc_state_rem_all_p=
lanes_for_stream
|   |-- drivers-gpu-drm-amd-amdgpu-..-display-dc-dc_dmub_srv.c:warning:Func=
tion-parameter-or-struct-member-context-not-described-in-populate_subvp_cmd=
_drr_info
|   |-- drivers-gpu-drm-msm-disp-dpu1-dpu_encoder.c:warning:Excess-struct-m=
ember-debugfs_root-description-in-dpu_encoder_virt
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-drv-=
not-described-in-kunit_device_register_with_driver
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-name=
-not-described-in-kunit_device_register
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-name=
-not-described-in-kunit_device_register_with_driver
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-name=
-not-described-in-kunit_driver_create
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-test=
-not-described-in-kunit_device_register
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-test=
-not-described-in-kunit_device_register_with_driver
|   `-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-test=
-not-described-in-kunit_driver_create
|-- nios2-allmodconfig
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-drv-=
not-described-in-kunit_device_register_with_driver
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-name=
-not-described-in-kunit_device_register
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-name=
-not-described-in-kunit_device_register_with_driver
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-name=
-not-described-in-kunit_driver_create
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-test=
-not-described-in-kunit_device_register
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-test=
-not-described-in-kunit_device_register_with_driver
|   `-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-test=
-not-described-in-kunit_driver_create
|-- nios2-allyesconfig
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-drv-=
not-described-in-kunit_device_register_with_driver
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-name=
-not-described-in-kunit_device_register
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-name=
-not-described-in-kunit_device_register_with_driver
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-name=
-not-described-in-kunit_driver_create
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-test=
-not-described-in-kunit_device_register
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-test=
-not-described-in-kunit_device_register_with_driver
|   `-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-test=
-not-described-in-kunit_driver_create
|-- nios2-randconfig-001-20231222
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-drv-=
not-described-in-kunit_device_register_with_driver
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-name=
-not-described-in-kunit_device_register
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-name=
-not-described-in-kunit_device_register_with_driver
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-name=
-not-described-in-kunit_driver_create
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-test=
-not-described-in-kunit_device_register
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-test=
-not-described-in-kunit_device_register_with_driver
|   `-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-test=
-not-described-in-kunit_driver_create
|-- nios2-randconfig-002-20231222
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-drv-=
not-described-in-kunit_device_register_with_driver
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-name=
-not-described-in-kunit_device_register
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-name=
-not-described-in-kunit_device_register_with_driver
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-name=
-not-described-in-kunit_driver_create
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-test=
-not-described-in-kunit_device_register
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-test=
-not-described-in-kunit_device_register_with_driver
|   `-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-test=
-not-described-in-kunit_driver_create
|-- nios2-randconfig-r064-20231222
|   |-- WARNING:modpost:missing-MODULE_DESCRIPTION()-in-lib-zlib_inflate-zl=
ib_inflate.o
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-drv-=
not-described-in-kunit_device_register_with_driver
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-name=
-not-described-in-kunit_device_register
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-name=
-not-described-in-kunit_device_register_with_driver
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-name=
-not-described-in-kunit_driver_create
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-test=
-not-described-in-kunit_device_register
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-test=
-not-described-in-kunit_device_register_with_driver
|   `-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-test=
-not-described-in-kunit_driver_create
|-- openrisc-allyesconfig
|   |-- drivers-gpu-drm-amd-amdgpu-..-display-dc-core-dc_state.c:warning:Ex=
cess-function-parameter-context-description-in-dc_state_rem_all_planes_for_=
stream
|   |-- drivers-gpu-drm-amd-amdgpu-..-display-dc-core-dc_state.c:warning:Fu=
nction-parameter-or-struct-member-state-not-described-in-dc_state_rem_all_p=
lanes_for_stream
|   |-- drivers-gpu-drm-amd-amdgpu-..-display-dc-dc_dmub_srv.c:warning:Func=
tion-parameter-or-struct-member-context-not-described-in-populate_subvp_cmd=
_drr_info
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-drv-=
not-described-in-kunit_device_register_with_driver
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-name=
-not-described-in-kunit_device_register
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-name=
-not-described-in-kunit_device_register_with_driver
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-name=
-not-described-in-kunit_driver_create
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-test=
-not-described-in-kunit_device_register
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-test=
-not-described-in-kunit_device_register_with_driver
|   `-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-test=
-not-described-in-kunit_driver_create
|-- parisc-allmodconfig
|   |-- WARNING:modpost:missing-MODULE_DESCRIPTION()-in-drivers-tty-serial-=
8250_parisc.o
|   |-- drivers-gpu-drm-amd-amdgpu-..-display-dc-core-dc_state.c:warning:Ex=
cess-function-parameter-context-description-in-dc_state_rem_all_planes_for_=
stream
|   |-- drivers-gpu-drm-amd-amdgpu-..-display-dc-core-dc_state.c:warning:Fu=
nction-parameter-or-struct-member-state-not-described-in-dc_state_rem_all_p=
lanes_for_stream
|   |-- drivers-gpu-drm-amd-amdgpu-..-display-dc-dc_dmub_srv.c:warning:Func=
tion-parameter-or-struct-member-context-not-described-in-populate_subvp_cmd=
_drr_info
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-drv-=
not-described-in-kunit_device_register_with_driver
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-name=
-not-described-in-kunit_device_register
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-name=
-not-described-in-kunit_device_register_with_driver
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-name=
-not-described-in-kunit_driver_create
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-test=
-not-described-in-kunit_device_register
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-test=
-not-described-in-kunit_device_register_with_driver
|   `-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-test=
-not-described-in-kunit_driver_create
|-- parisc-allyesconfig
|   |-- drivers-gpu-drm-amd-amdgpu-..-display-dc-core-dc_state.c:warning:Ex=
cess-function-parameter-context-description-in-dc_state_rem_all_planes_for_=
stream
|   |-- drivers-gpu-drm-amd-amdgpu-..-display-dc-core-dc_state.c:warning:Fu=
nction-parameter-or-struct-member-state-not-described-in-dc_state_rem_all_p=
lanes_for_stream
|   |-- drivers-gpu-drm-amd-amdgpu-..-display-dc-dc_dmub_srv.c:warning:Func=
tion-parameter-or-struct-member-context-not-described-in-populate_subvp_cmd=
_drr_info
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-drv-=
not-described-in-kunit_device_register_with_driver
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-name=
-not-described-in-kunit_device_register
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-name=
-not-described-in-kunit_device_register_with_driver
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-name=
-not-described-in-kunit_driver_create
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-test=
-not-described-in-kunit_device_register
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-test=
-not-described-in-kunit_device_register_with_driver
|   `-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-test=
-not-described-in-kunit_driver_create
|-- parisc-randconfig-001-20231222
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-drv-=
not-described-in-kunit_device_register_with_driver
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-name=
-not-described-in-kunit_device_register
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-name=
-not-described-in-kunit_device_register_with_driver
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-name=
-not-described-in-kunit_driver_create
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-test=
-not-described-in-kunit_device_register
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-test=
-not-described-in-kunit_device_register_with_driver
|   `-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-test=
-not-described-in-kunit_driver_create
|-- powerpc-ppc64_defconfig
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-drv-=
not-described-in-kunit_device_register_with_driver
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-name=
-not-described-in-kunit_device_register
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-name=
-not-described-in-kunit_device_register_with_driver
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-name=
-not-described-in-kunit_driver_create
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-test=
-not-described-in-kunit_device_register
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-test=
-not-described-in-kunit_device_register_with_driver
|   `-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-test=
-not-described-in-kunit_driver_create
|-- powerpc-randconfig-001-20231222
|   |-- drivers-gpu-drm-amd-amdgpu-..-display-dc-core-dc_state.c:warning:Ex=
cess-function-parameter-context-description-in-dc_state_rem_all_planes_for_=
stream
|   |-- drivers-gpu-drm-amd-amdgpu-..-display-dc-core-dc_state.c:warning:Fu=
nction-parameter-or-struct-member-state-not-described-in-dc_state_rem_all_p=
lanes_for_stream
|   |-- drivers-gpu-drm-amd-amdgpu-..-display-dc-dc_dmub_srv.c:warning:Func=
tion-parameter-or-struct-member-context-not-described-in-populate_subvp_cmd=
_drr_info
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-drv-=
not-described-in-kunit_device_register_with_driver
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-name=
-not-described-in-kunit_device_register
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-name=
-not-described-in-kunit_device_register_with_driver
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-name=
-not-described-in-kunit_driver_create
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-test=
-not-described-in-kunit_device_register
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-test=
-not-described-in-kunit_device_register_with_driver
|   `-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-test=
-not-described-in-kunit_driver_create
|-- powerpc-randconfig-002-20231222
|   |-- drivers-gpu-drm-amd-amdgpu-..-display-dc-core-dc_state.c:warning:Ex=
cess-function-parameter-context-description-in-dc_state_rem_all_planes_for_=
stream
|   |-- drivers-gpu-drm-amd-amdgpu-..-display-dc-core-dc_state.c:warning:Fu=
nction-parameter-or-struct-member-state-not-described-in-dc_state_rem_all_p=
lanes_for_stream
|   |-- drivers-gpu-drm-amd-amdgpu-..-display-dc-dc_dmub_srv.c:warning:Func=
tion-parameter-or-struct-member-context-not-described-in-populate_subvp_cmd=
_drr_info
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-drv-=
not-described-in-kunit_device_register_with_driver
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-name=
-not-described-in-kunit_device_register
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-name=
-not-described-in-kunit_device_register_with_driver
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-name=
-not-described-in-kunit_driver_create
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-test=
-not-described-in-kunit_device_register
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-test=
-not-described-in-kunit_device_register_with_driver
|   `-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-test=
-not-described-in-kunit_driver_create
|-- powerpc-randconfig-003-20231222
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-drv-=
not-described-in-kunit_device_register_with_driver
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-name=
-not-described-in-kunit_device_register
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-name=
-not-described-in-kunit_device_register_with_driver
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-name=
-not-described-in-kunit_driver_create
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-test=
-not-described-in-kunit_device_register
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-test=
-not-described-in-kunit_device_register_with_driver
|   `-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-test=
-not-described-in-kunit_driver_create
|-- powerpc64-randconfig-001-20231222
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-drv-=
not-described-in-kunit_device_register_with_driver
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-name=
-not-described-in-kunit_device_register
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-name=
-not-described-in-kunit_device_register_with_driver
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-name=
-not-described-in-kunit_driver_create
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-test=
-not-described-in-kunit_device_register
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-test=
-not-described-in-kunit_device_register_with_driver
|   `-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-test=
-not-described-in-kunit_driver_create
|-- powerpc64-randconfig-002-20231222
|   |-- drivers-gpu-drm-amd-amdgpu-..-display-dc-core-dc_state.c:warning:Ex=
cess-function-parameter-context-description-in-dc_state_rem_all_planes_for_=
stream
|   |-- drivers-gpu-drm-amd-amdgpu-..-display-dc-core-dc_state.c:warning:Fu=
nction-parameter-or-struct-member-state-not-described-in-dc_state_rem_all_p=
lanes_for_stream
|   |-- drivers-gpu-drm-amd-amdgpu-..-display-dc-dc_dmub_srv.c:warning:Func=
tion-parameter-or-struct-member-context-not-described-in-populate_subvp_cmd=
_drr_info
|   |-- drivers-gpu-drm-amd-amdgpu-..-display-dc-hwss-dcn35-dcn35_hwseq.c:w=
arning:This-comment-starts-with-but-isn-t-a-kernel-doc-comment.-Refer-Docum=
entation-doc-guide-kernel-doc.rst
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-drv-=
not-described-in-kunit_device_register_with_driver
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-name=
-not-described-in-kunit_device_register
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-name=
-not-described-in-kunit_device_register_with_driver
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-name=
-not-described-in-kunit_driver_create
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-test=
-not-described-in-kunit_device_register
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-test=
-not-described-in-kunit_device_register_with_driver
|   `-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-test=
-not-described-in-kunit_driver_create
|-- powerpc64-randconfig-003-20231222
|   |-- drivers-gpu-drm-amd-amdgpu-..-display-dc-core-dc_state.c:warning:Ex=
cess-function-parameter-context-description-in-dc_state_rem_all_planes_for_=
stream
|   |-- drivers-gpu-drm-amd-amdgpu-..-display-dc-core-dc_state.c:warning:Fu=
nction-parameter-or-struct-member-state-not-described-in-dc_state_rem_all_p=
lanes_for_stream
|   |-- drivers-gpu-drm-amd-amdgpu-..-display-dc-dc_dmub_srv.c:warning:Func=
tion-parameter-or-struct-member-context-not-described-in-populate_subvp_cmd=
_drr_info
|   |-- drivers-gpu-drm-amd-amdgpu-..-display-dc-hwss-dcn35-dcn35_hwseq.c:w=
arning:This-comment-starts-with-but-isn-t-a-kernel-doc-comment.-Refer-Docum=
entation-doc-guide-kernel-doc.rst
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-drv-=
not-described-in-kunit_device_register_with_driver
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-name=
-not-described-in-kunit_device_register
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-name=
-not-described-in-kunit_device_register_with_driver
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-name=
-not-described-in-kunit_driver_create
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-test=
-not-described-in-kunit_device_register
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-test=
-not-described-in-kunit_device_register_with_driver
|   `-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-test=
-not-described-in-kunit_driver_create
|-- powerpc64-randconfig-r035-20211208
|   `-- powerpc64-linux-ld:warning:orphan-section-bss..Lubsan_data794-from-=
kernel-ptrace.o-being-placed-in-section-.bss..Lubsan_data794
|-- powerpc64-randconfig-r113-20231222
|   |-- drivers-hwmon-max31827.c:sparse:sparse:dubious:x-y
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-drv-=
not-described-in-kunit_device_register_with_driver
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-name=
-not-described-in-kunit_device_register
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-name=
-not-described-in-kunit_device_register_with_driver
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-name=
-not-described-in-kunit_driver_create
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-test=
-not-described-in-kunit_device_register
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-test=
-not-described-in-kunit_device_register_with_driver
|   `-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-test=
-not-described-in-kunit_driver_create
|-- riscv-allmodconfig
|   |-- drivers-gpu-drm-amd-amdgpu-..-display-dc-core-dc_state.c:warning:Ex=
cess-function-parameter-context-description-in-dc_state_rem_all_planes_for_=
stream
|   |-- drivers-gpu-drm-amd-amdgpu-..-display-dc-core-dc_state.c:warning:Fu=
nction-parameter-or-struct-member-state-not-described-in-dc_state_rem_all_p=
lanes_for_stream
|   |-- drivers-gpu-drm-amd-amdgpu-..-display-dc-dc_dmub_srv.c:warning:Func=
tion-parameter-or-struct-member-context-not-described-in-populate_subvp_cmd=
_drr_info
|   |-- drivers-gpu-drm-msm-disp-dpu1-dpu_encoder.c:warning:Excess-struct-m=
ember-debugfs_root-description-in-dpu_encoder_virt
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-drv-=
not-described-in-kunit_device_register_with_driver
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-name=
-not-described-in-kunit_device_register
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-name=
-not-described-in-kunit_device_register_with_driver
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-name=
-not-described-in-kunit_driver_create
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-test=
-not-described-in-kunit_device_register
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-test=
-not-described-in-kunit_device_register_with_driver
|   `-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-test=
-not-described-in-kunit_driver_create
|-- riscv-allyesconfig
|   |-- drivers-gpu-drm-amd-amdgpu-..-display-dc-core-dc_state.c:warning:Ex=
cess-function-parameter-context-description-in-dc_state_rem_all_planes_for_=
stream
|   |-- drivers-gpu-drm-amd-amdgpu-..-display-dc-core-dc_state.c:warning:Fu=
nction-parameter-or-struct-member-state-not-described-in-dc_state_rem_all_p=
lanes_for_stream
|   |-- drivers-gpu-drm-amd-amdgpu-..-display-dc-dc_dmub_srv.c:warning:Func=
tion-parameter-or-struct-member-context-not-described-in-populate_subvp_cmd=
_drr_info
|   |-- drivers-gpu-drm-msm-disp-dpu1-dpu_encoder.c:warning:Excess-struct-m=
ember-debugfs_root-description-in-dpu_encoder_virt
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-drv-=
not-described-in-kunit_device_register_with_driver
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-name=
-not-described-in-kunit_device_register
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-name=
-not-described-in-kunit_device_register_with_driver
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-name=
-not-described-in-kunit_driver_create
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-test=
-not-described-in-kunit_device_register
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-test=
-not-described-in-kunit_device_register_with_driver
|   `-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-test=
-not-described-in-kunit_driver_create
|-- riscv-randconfig-002-20231222
|   |-- drivers-gpu-drm-msm-disp-dpu1-dpu_encoder.c:warning:Excess-struct-m=
ember-debugfs_root-description-in-dpu_encoder_virt
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-drv-=
not-described-in-kunit_device_register_with_driver
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-name=
-not-described-in-kunit_device_register
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-name=
-not-described-in-kunit_device_register_with_driver
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-name=
-not-described-in-kunit_driver_create
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-test=
-not-described-in-kunit_device_register
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-test=
-not-described-in-kunit_device_register_with_driver
|   `-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-test=
-not-described-in-kunit_driver_create
|-- s390-allmodconfig
|   |-- WARNING:modpost:missing-MODULE_DESCRIPTION()-in-drivers-s390-block-=
dasd_diag_mod.o
|   |-- WARNING:modpost:missing-MODULE_DESCRIPTION()-in-drivers-s390-block-=
dasd_eckd_mod.o
|   |-- WARNING:modpost:missing-MODULE_DESCRIPTION()-in-drivers-s390-block-=
dasd_fba_mod.o
|   |-- drivers-gpu-drm-amd-amdgpu-..-display-dc-core-dc_state.c:warning:Ex=
cess-function-parameter-context-description-in-dc_state_rem_all_planes_for_=
stream
|   |-- drivers-gpu-drm-amd-amdgpu-..-display-dc-core-dc_state.c:warning:Fu=
nction-parameter-or-struct-member-state-not-described-in-dc_state_rem_all_p=
lanes_for_stream
|   |-- drivers-gpu-drm-amd-amdgpu-..-display-dc-dc_dmub_srv.c:warning:Func=
tion-parameter-or-struct-member-context-not-described-in-populate_subvp_cmd=
_drr_info
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-drv-=
not-described-in-kunit_device_register_with_driver
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-name=
-not-described-in-kunit_device_register
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-name=
-not-described-in-kunit_device_register_with_driver
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-name=
-not-described-in-kunit_driver_create
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-test=
-not-described-in-kunit_device_register
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-test=
-not-described-in-kunit_device_register_with_driver
|   `-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-test=
-not-described-in-kunit_driver_create
|-- s390-allyesconfig
|   |-- drivers-gpu-drm-amd-amdgpu-..-display-dc-core-dc_state.c:warning:Ex=
cess-function-parameter-context-description-in-dc_state_rem_all_planes_for_=
stream
|   |-- drivers-gpu-drm-amd-amdgpu-..-display-dc-core-dc_state.c:warning:Fu=
nction-parameter-or-struct-member-state-not-described-in-dc_state_rem_all_p=
lanes_for_stream
|   |-- drivers-gpu-drm-amd-amdgpu-..-display-dc-dc_dmub_srv.c:warning:Func=
tion-parameter-or-struct-member-context-not-described-in-populate_subvp_cmd=
_drr_info
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-drv-=
not-described-in-kunit_device_register_with_driver
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-name=
-not-described-in-kunit_device_register
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-name=
-not-described-in-kunit_device_register_with_driver
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-name=
-not-described-in-kunit_driver_create
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-test=
-not-described-in-kunit_device_register
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-test=
-not-described-in-kunit_device_register_with_driver
|   `-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-test=
-not-described-in-kunit_driver_create
|-- s390-defconfig
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-drv-=
not-described-in-kunit_device_register_with_driver
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-name=
-not-described-in-kunit_device_register
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-name=
-not-described-in-kunit_device_register_with_driver
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-name=
-not-described-in-kunit_driver_create
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-test=
-not-described-in-kunit_device_register
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-test=
-not-described-in-kunit_device_register_with_driver
|   `-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-test=
-not-described-in-kunit_driver_create
|-- sh-allmodconfig
|   |-- include-linux-syscalls.h:internal-compiler-error:in-change_address_=
1-at-emit-rtl.cc
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-drv-=
not-described-in-kunit_device_register_with_driver
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-name=
-not-described-in-kunit_device_register
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-name=
-not-described-in-kunit_device_register_with_driver
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-name=
-not-described-in-kunit_driver_create
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-test=
-not-described-in-kunit_device_register
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-test=
-not-described-in-kunit_device_register_with_driver
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-test=
-not-described-in-kunit_driver_create
|   `-- standard-input:Error:pcrel-too-far
|-- sh-allnoconfig
|   |-- standard-input:Error:pcrel-too-far
|   `-- standard-input:Warning:overflow-in-branch-to-.L1609-converted-into-=
longer-instruction-sequence
|-- sh-allyesconfig
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-drv-=
not-described-in-kunit_device_register_with_driver
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-name=
-not-described-in-kunit_device_register
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-name=
-not-described-in-kunit_device_register_with_driver
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-name=
-not-described-in-kunit_driver_create
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-test=
-not-described-in-kunit_device_register
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-test=
-not-described-in-kunit_device_register_with_driver
|   `-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-test=
-not-described-in-kunit_driver_create
|-- sh-randconfig-001-20231222
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-drv-=
not-described-in-kunit_device_register_with_driver
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-name=
-not-described-in-kunit_device_register
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-name=
-not-described-in-kunit_device_register_with_driver
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-name=
-not-described-in-kunit_driver_create
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-test=
-not-described-in-kunit_device_register
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-test=
-not-described-in-kunit_device_register_with_driver
|   `-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-test=
-not-described-in-kunit_driver_create
|-- sh-randconfig-002-20231222
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-drv-=
not-described-in-kunit_device_register_with_driver
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-name=
-not-described-in-kunit_device_register
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-name=
-not-described-in-kunit_device_register_with_driver
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-name=
-not-described-in-kunit_driver_create
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-test=
-not-described-in-kunit_device_register
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-test=
-not-described-in-kunit_device_register_with_driver
|   `-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-test=
-not-described-in-kunit_driver_create
|-- sh-randconfig-r032-20220320
|   `-- standard-input:Warning:overflow-in-branch-to-.L4838-converted-into-=
longer-instruction-sequence
|-- sh-randconfig-r123-20231222
|   |-- fs-bcachefs-btree_iter.c:sparse:sparse:incompatible-types-in-compar=
ison-expression-(different-address-spaces):
|   |-- fs-bcachefs-btree_locking.c:sparse:sparse:incompatible-types-in-com=
parison-expression-(different-address-spaces):
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-drv-=
not-described-in-kunit_device_register_with_driver
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-name=
-not-described-in-kunit_device_register
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-name=
-not-described-in-kunit_device_register_with_driver
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-name=
-not-described-in-kunit_driver_create
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-test=
-not-described-in-kunit_device_register
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-test=
-not-described-in-kunit_device_register_with_driver
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-test=
-not-described-in-kunit_driver_create
|   |-- standard-input:Error:pcrel-too-far
|   `-- standard-input:Warning:overflow-in-branch-to-.L1661-converted-into-=
longer-instruction-sequence
|-- sparc-allmodconfig
|   |-- arch-sparc-kernel-module.c:warning:variable-strtab-set-but-not-used
|   |-- arch-sparc-mm-init_64.c:warning:variable-hv_pgsz_idx-set-but-not-us=
ed
|   |-- drivers-gpu-drm-amd-amdgpu-..-display-dc-core-dc_state.c:warning:Ex=
cess-function-parameter-context-description-in-dc_state_rem_all_planes_for_=
stream
|   |-- drivers-gpu-drm-amd-amdgpu-..-display-dc-core-dc_state.c:warning:Fu=
nction-parameter-or-struct-member-state-not-described-in-dc_state_rem_all_p=
lanes_for_stream
|   |-- drivers-gpu-drm-amd-amdgpu-..-display-dc-dc_dmub_srv.c:warning:Func=
tion-parameter-or-struct-member-context-not-described-in-populate_subvp_cmd=
_drr_info
|   |-- drivers-gpu-drm-msm-disp-dpu1-dpu_encoder.c:warning:Excess-struct-m=
ember-debugfs_root-description-in-dpu_encoder_virt
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-drv-=
not-described-in-kunit_device_register_with_driver
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-name=
-not-described-in-kunit_device_register
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-name=
-not-described-in-kunit_device_register_with_driver
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-name=
-not-described-in-kunit_driver_create
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-test=
-not-described-in-kunit_device_register
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-test=
-not-described-in-kunit_device_register_with_driver
|   `-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-test=
-not-described-in-kunit_driver_create
|-- sparc-allnoconfig
|   |-- arch-sparc-mm-leon_mm.c:warning:variable-paddrbase-set-but-not-used
|   `-- arch-sparc-mm-srmmu.c:warning:variable-clear-set-but-not-used
|-- sparc-defconfig
|   |-- arch-sparc-kernel-module.c:warning:variable-strtab-set-but-not-used
|   |-- arch-sparc-mm-leon_mm.c:warning:variable-paddrbase-set-but-not-used
|   `-- arch-sparc-mm-srmmu.c:warning:variable-clear-set-but-not-used
|-- sparc-randconfig-001-20231222
|   `-- arch-sparc-mm-init_64.c:warning:variable-hv_pgsz_idx-set-but-not-us=
ed
|-- sparc-randconfig-002-20231222
|   |-- arch-sparc-mm-init_64.c:warning:variable-hv_pgsz_idx-set-but-not-us=
ed
|   |-- arch-sparc-mm-init_64.c:warning:variable-pagecv_flag-set-but-not-us=
ed
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-drv-=
not-described-in-kunit_device_register_with_driver
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-name=
-not-described-in-kunit_device_register
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-name=
-not-described-in-kunit_device_register_with_driver
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-name=
-not-described-in-kunit_driver_create
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-test=
-not-described-in-kunit_device_register
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-test=
-not-described-in-kunit_device_register_with_driver
|   `-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-test=
-not-described-in-kunit_driver_create
|-- sparc-randconfig-r133-20231222
|   |-- (.head.text):relocation-truncated-to-fit:R_SPARC_WDISP22-against-in=
it.text
|   |-- arch-sparc-kernel-module.c:warning:variable-strtab-set-but-not-used
|   |-- arch-sparc-mm-leon_mm.c:warning:variable-paddrbase-set-but-not-used
|   |-- arch-sparc-mm-srmmu.c:warning:variable-clear-set-but-not-used
|   |-- fs-bcachefs-btree_iter.c:sparse:sparse:incompatible-types-in-compar=
ison-expression-(different-address-spaces):
|   |-- fs-bcachefs-btree_locking.c:sparse:sparse:incompatible-types-in-com=
parison-expression-(different-address-spaces):
|   |-- parport_pc.c:(.text):undefined-reference-to-ebus_dma_enable
|   |-- parport_pc.c:(.text):undefined-reference-to-ebus_dma_irq_enable
|   |-- parport_pc.c:(.text):undefined-reference-to-ebus_dma_register
|   |-- sparc-linux-ld:parport_pc.c:(.text):undefined-reference-to-ebus_dma=
_enable
|   |-- sparc-linux-ld:parport_pc.c:(.text):undefined-reference-to-ebus_dma=
_irq_enable
|   |-- sparc-linux-ld:parport_pc.c:(.text):undefined-reference-to-ebus_dma=
_prepare
|   |-- sparc-linux-ld:parport_pc.c:(.text):undefined-reference-to-ebus_dma=
_request
|   |-- sparc-linux-ld:parport_pc.c:(.text):undefined-reference-to-ebus_dma=
_residue
|   `-- sparc-linux-ld:parport_pc.c:(.text):undefined-reference-to-ebus_dma=
_unregister
|-- sparc64-allmodconfig
|   |-- arch-sparc-kernel-module.c:warning:variable-strtab-set-but-not-used
|   |-- arch-sparc-mm-init_64.c:warning:variable-hv_pgsz_idx-set-but-not-us=
ed
|   |-- drivers-gpu-drm-amd-amdgpu-..-display-dc-core-dc_state.c:warning:Ex=
cess-function-parameter-context-description-in-dc_state_rem_all_planes_for_=
stream
|   |-- drivers-gpu-drm-amd-amdgpu-..-display-dc-core-dc_state.c:warning:Fu=
nction-parameter-or-struct-member-state-not-described-in-dc_state_rem_all_p=
lanes_for_stream
|   |-- drivers-gpu-drm-amd-amdgpu-..-display-dc-dc_dmub_srv.c:warning:Func=
tion-parameter-or-struct-member-context-not-described-in-populate_subvp_cmd=
_drr_info
|   |-- drivers-gpu-drm-msm-disp-dpu1-dpu_encoder.c:warning:Excess-struct-m=
ember-debugfs_root-description-in-dpu_encoder_virt
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-drv-=
not-described-in-kunit_device_register_with_driver
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-name=
-not-described-in-kunit_device_register
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-name=
-not-described-in-kunit_device_register_with_driver
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-name=
-not-described-in-kunit_driver_create
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-test=
-not-described-in-kunit_device_register
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-test=
-not-described-in-kunit_device_register_with_driver
|   `-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-test=
-not-described-in-kunit_driver_create
|-- sparc64-allyesconfig
|   |-- arch-sparc-kernel-module.c:warning:variable-strtab-set-but-not-used
|   |-- arch-sparc-mm-init_64.c:warning:variable-hv_pgsz_idx-set-but-not-us=
ed
|   |-- drivers-gpu-drm-amd-amdgpu-..-display-dc-core-dc_state.c:warning:Ex=
cess-function-parameter-context-description-in-dc_state_rem_all_planes_for_=
stream
|   |-- drivers-gpu-drm-amd-amdgpu-..-display-dc-core-dc_state.c:warning:Fu=
nction-parameter-or-struct-member-state-not-described-in-dc_state_rem_all_p=
lanes_for_stream
|   |-- drivers-gpu-drm-amd-amdgpu-..-display-dc-dc_dmub_srv.c:warning:Func=
tion-parameter-or-struct-member-context-not-described-in-populate_subvp_cmd=
_drr_info
|   |-- drivers-gpu-drm-msm-disp-dpu1-dpu_encoder.c:warning:Excess-struct-m=
ember-debugfs_root-description-in-dpu_encoder_virt
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-drv-=
not-described-in-kunit_device_register_with_driver
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-name=
-not-described-in-kunit_device_register
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-name=
-not-described-in-kunit_device_register_with_driver
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-name=
-not-described-in-kunit_driver_create
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-test=
-not-described-in-kunit_device_register
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-test=
-not-described-in-kunit_device_register_with_driver
|   `-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-test=
-not-described-in-kunit_driver_create
|-- sparc64-defconfig
|   |-- arch-sparc-kernel-module.c:warning:variable-strtab-set-but-not-used
|   `-- arch-sparc-mm-init_64.c:warning:variable-hv_pgsz_idx-set-but-not-us=
ed
|-- sparc64-randconfig-001-20231222
|   |-- arch-sparc-kernel-module.c:warning:variable-strtab-set-but-not-used
|   |-- arch-sparc-mm-init_64.c:warning:variable-pagecv_flag-set-but-not-us=
ed
|   |-- drivers-gpu-drm-amd-amdgpu-..-display-dc-core-dc_state.c:warning:Ex=
cess-function-parameter-context-description-in-dc_state_rem_all_planes_for_=
stream
|   |-- drivers-gpu-drm-amd-amdgpu-..-display-dc-core-dc_state.c:warning:Fu=
nction-parameter-or-struct-member-state-not-described-in-dc_state_rem_all_p=
lanes_for_stream
|   |-- drivers-gpu-drm-amd-amdgpu-..-display-dc-dc_dmub_srv.c:warning:Func=
tion-parameter-or-struct-member-context-not-described-in-populate_subvp_cmd=
_drr_info
|   `-- fbcon.c:(.text):undefined-reference-to-fb_is_primary_device
|-- sparc64-randconfig-002-20231222
|   `-- arch-sparc-kernel-module.c:warning:variable-strtab-set-but-not-used
|-- x86_64-allnoconfig
|   `-- include-linux-sched.h:linux-cache.h-is-included-more-than-once.
|-- x86_64-buildonly-randconfig-001-20231222
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-drv-=
not-described-in-kunit_device_register_with_driver
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-name=
-not-described-in-kunit_device_register
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-name=
-not-described-in-kunit_device_register_with_driver
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-name=
-not-described-in-kunit_driver_create
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-test=
-not-described-in-kunit_device_register
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-test=
-not-described-in-kunit_device_register_with_driver
|   `-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-test=
-not-described-in-kunit_driver_create
|-- x86_64-buildonly-randconfig-002-20231222
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-drv-=
not-described-in-kunit_device_register_with_driver
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-name=
-not-described-in-kunit_device_register
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-name=
-not-described-in-kunit_device_register_with_driver
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-name=
-not-described-in-kunit_driver_create
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-test=
-not-described-in-kunit_device_register
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-test=
-not-described-in-kunit_device_register_with_driver
|   `-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-test=
-not-described-in-kunit_driver_create
|-- x86_64-buildonly-randconfig-003-20231222
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-drv-=
not-described-in-kunit_device_register_with_driver
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-name=
-not-described-in-kunit_device_register
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-name=
-not-described-in-kunit_device_register_with_driver
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-name=
-not-described-in-kunit_driver_create
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-test=
-not-described-in-kunit_device_register
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-test=
-not-described-in-kunit_device_register_with_driver
|   `-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-test=
-not-described-in-kunit_driver_create
|-- x86_64-buildonly-randconfig-004-20231222
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-drv-=
not-described-in-kunit_device_register_with_driver
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-name=
-not-described-in-kunit_device_register
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-name=
-not-described-in-kunit_device_register_with_driver
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-name=
-not-described-in-kunit_driver_create
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-test=
-not-described-in-kunit_device_register
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-test=
-not-described-in-kunit_device_register_with_driver
|   `-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-test=
-not-described-in-kunit_driver_create
|-- x86_64-buildonly-randconfig-005-20231222
|   |-- drivers-gpu-drm-amd-amdgpu-..-display-dc-core-dc_state.c:warning:Ex=
cess-function-parameter-context-description-in-dc_state_rem_all_planes_for_=
stream
|   |-- drivers-gpu-drm-amd-amdgpu-..-display-dc-core-dc_state.c:warning:Fu=
nction-parameter-or-struct-member-state-not-described-in-dc_state_rem_all_p=
lanes_for_stream
|   |-- drivers-gpu-drm-amd-amdgpu-..-display-dc-dc_dmub_srv.c:warning:Func=
tion-parameter-or-struct-member-context-not-described-in-populate_subvp_cmd=
_drr_info
|   |-- drivers-gpu-drm-amd-amdgpu-..-display-dc-hwss-dcn35-dcn35_hwseq.c:w=
arning:This-comment-starts-with-but-isn-t-a-kernel-doc-comment.-Refer-Docum=
entation-doc-guide-kernel-doc.rst
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-drv-=
not-described-in-kunit_device_register_with_driver
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-name=
-not-described-in-kunit_device_register
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-name=
-not-described-in-kunit_device_register_with_driver
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-name=
-not-described-in-kunit_driver_create
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-test=
-not-described-in-kunit_device_register
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-test=
-not-described-in-kunit_device_register_with_driver
|   `-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-test=
-not-described-in-kunit_driver_create
|-- x86_64-buildonly-randconfig-006-20231222
|   |-- drivers-gpu-drm-amd-amdgpu-..-display-dc-core-dc_state.c:warning:Ex=
cess-function-parameter-context-description-in-dc_state_rem_all_planes_for_=
stream
|   |-- drivers-gpu-drm-amd-amdgpu-..-display-dc-core-dc_state.c:warning:Fu=
nction-parameter-or-struct-member-state-not-described-in-dc_state_rem_all_p=
lanes_for_stream
|   |-- drivers-gpu-drm-amd-amdgpu-..-display-dc-dc_dmub_srv.c:warning:Func=
tion-parameter-or-struct-member-context-not-described-in-populate_subvp_cmd=
_drr_info
|   |-- drivers-gpu-drm-amd-amdgpu-..-display-dc-hwss-dcn35-dcn35_hwseq.c:w=
arning:This-comment-starts-with-but-isn-t-a-kernel-doc-comment.-Refer-Docum=
entation-doc-guide-kernel-doc.rst
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-drv-=
not-described-in-kunit_device_register_with_driver
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-name=
-not-described-in-kunit_device_register
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-name=
-not-described-in-kunit_device_register_with_driver
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-name=
-not-described-in-kunit_driver_create
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-test=
-not-described-in-kunit_device_register
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-test=
-not-described-in-kunit_device_register_with_driver
|   `-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-test=
-not-described-in-kunit_driver_create
|-- x86_64-randconfig-011-20231222
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-drv-=
not-described-in-kunit_device_register_with_driver
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-name=
-not-described-in-kunit_device_register
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-name=
-not-described-in-kunit_device_register_with_driver
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-name=
-not-described-in-kunit_driver_create
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-test=
-not-described-in-kunit_device_register
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-test=
-not-described-in-kunit_device_register_with_driver
|   `-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-test=
-not-described-in-kunit_driver_create
|-- x86_64-randconfig-014-20231222
|   |-- drivers-gpu-drm-amd-amdgpu-..-display-dc-core-dc_state.c:warning:Ex=
cess-function-parameter-context-description-in-dc_state_rem_all_planes_for_=
stream
|   |-- drivers-gpu-drm-amd-amdgpu-..-display-dc-core-dc_state.c:warning:Fu=
nction-parameter-or-struct-member-state-not-described-in-dc_state_rem_all_p=
lanes_for_stream
|   |-- drivers-gpu-drm-amd-amdgpu-..-display-dc-dc_dmub_srv.c:warning:Func=
tion-parameter-or-struct-member-context-not-described-in-populate_subvp_cmd=
_drr_info
|   |-- drivers-gpu-drm-amd-amdgpu-..-display-dc-hwss-dcn35-dcn35_hwseq.c:w=
arning:This-comment-starts-with-but-isn-t-a-kernel-doc-comment.-Refer-Docum=
entation-doc-guide-kernel-doc.rst
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-drv-=
not-described-in-kunit_device_register_with_driver
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-name=
-not-described-in-kunit_device_register
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-name=
-not-described-in-kunit_device_register_with_driver
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-name=
-not-described-in-kunit_driver_create
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-test=
-not-described-in-kunit_device_register
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-test=
-not-described-in-kunit_device_register_with_driver
|   `-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-test=
-not-described-in-kunit_driver_create
|-- x86_64-randconfig-015-20231222
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-drv-=
not-described-in-kunit_device_register_with_driver
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-name=
-not-described-in-kunit_device_register
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-name=
-not-described-in-kunit_device_register_with_driver
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-name=
-not-described-in-kunit_driver_create
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-test=
-not-described-in-kunit_device_register
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-test=
-not-described-in-kunit_device_register_with_driver
|   `-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-test=
-not-described-in-kunit_driver_create
|-- x86_64-randconfig-072-20231222
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-drv-=
not-described-in-kunit_device_register_with_driver
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-name=
-not-described-in-kunit_device_register
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-name=
-not-described-in-kunit_device_register_with_driver
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-name=
-not-described-in-kunit_driver_create
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-test=
-not-described-in-kunit_device_register
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-test=
-not-described-in-kunit_device_register_with_driver
|   `-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-test=
-not-described-in-kunit_driver_create
|-- x86_64-randconfig-073-20231222
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-drv-=
not-described-in-kunit_device_register_with_driver
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-name=
-not-described-in-kunit_device_register
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-name=
-not-described-in-kunit_device_register_with_driver
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-name=
-not-described-in-kunit_driver_create
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-test=
-not-described-in-kunit_device_register
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-test=
-not-described-in-kunit_device_register_with_driver
|   `-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-test=
-not-described-in-kunit_driver_create
|-- x86_64-randconfig-075-20231222
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-drv-=
not-described-in-kunit_device_register_with_driver
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-name=
-not-described-in-kunit_device_register
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-name=
-not-described-in-kunit_device_register_with_driver
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-name=
-not-described-in-kunit_driver_create
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-test=
-not-described-in-kunit_device_register
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-test=
-not-described-in-kunit_device_register_with_driver
|   `-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-test=
-not-described-in-kunit_driver_create
|-- x86_64-randconfig-076-20231222
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-drv-=
not-described-in-kunit_device_register_with_driver
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-name=
-not-described-in-kunit_device_register
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-name=
-not-described-in-kunit_device_register_with_driver
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-name=
-not-described-in-kunit_driver_create
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-test=
-not-described-in-kunit_device_register
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-test=
-not-described-in-kunit_device_register_with_driver
|   `-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-test=
-not-described-in-kunit_driver_create
|-- x86_64-randconfig-101-20231222
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-drv-=
not-described-in-kunit_device_register_with_driver
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-name=
-not-described-in-kunit_device_register
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-name=
-not-described-in-kunit_device_register_with_driver
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-name=
-not-described-in-kunit_driver_create
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-test=
-not-described-in-kunit_device_register
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-test=
-not-described-in-kunit_device_register_with_driver
|   `-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-test=
-not-described-in-kunit_driver_create
|-- x86_64-randconfig-102-20231222
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-drv-=
not-described-in-kunit_device_register_with_driver
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-name=
-not-described-in-kunit_device_register
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-name=
-not-described-in-kunit_device_register_with_driver
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-name=
-not-described-in-kunit_driver_create
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-test=
-not-described-in-kunit_device_register
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-test=
-not-described-in-kunit_device_register_with_driver
|   `-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-test=
-not-described-in-kunit_driver_create
|-- x86_64-randconfig-103-20231222
|   |-- drivers-gpu-drm-amd-amdgpu-..-display-dc-core-dc_state.c:warning:Ex=
cess-function-parameter-context-description-in-dc_state_rem_all_planes_for_=
stream
|   |-- drivers-gpu-drm-amd-amdgpu-..-display-dc-core-dc_state.c:warning:Fu=
nction-parameter-or-struct-member-state-not-described-in-dc_state_rem_all_p=
lanes_for_stream
|   |-- drivers-gpu-drm-amd-amdgpu-..-display-dc-dc_dmub_srv.c:warning:Func=
tion-parameter-or-struct-member-context-not-described-in-populate_subvp_cmd=
_drr_info
|   |-- drivers-gpu-drm-amd-amdgpu-..-display-dc-hwss-dcn35-dcn35_hwseq.c:w=
arning:This-comment-starts-with-but-isn-t-a-kernel-doc-comment.-Refer-Docum=
entation-doc-guide-kernel-doc.rst
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-drv-=
not-described-in-kunit_device_register_with_driver
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-name=
-not-described-in-kunit_device_register
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-name=
-not-described-in-kunit_device_register_with_driver
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-name=
-not-described-in-kunit_driver_create
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-test=
-not-described-in-kunit_device_register
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-test=
-not-described-in-kunit_device_register_with_driver
|   `-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-test=
-not-described-in-kunit_driver_create
|-- x86_64-randconfig-161-20231222
|   |-- drivers-atm-idt77252.c-idt77252_rx_raw()-warn:possible-spectre-seco=
nd-half.-vc
|   |-- drivers-atm-idt77252.c-idt77252_rx_raw()-warn:potential-spectre-iss=
ue-card-vcs-r
|   |-- drivers-dma-xilinx-xdma.c-xdma_channel_isr()-error:potentially-dere=
ferencing-uninitialized-desc-.
|   |-- drivers-hwmon-pmbus-ltc4286.c-ltc4286_probe()-warn:passing-zero-to-=
dev_err_probe
|   |-- drivers-scsi-mpi3mr-mpi3mr_app.c-mpi3mr_bsg_build_sgl()-warn:missin=
g-unwind-goto
|   |-- drivers-scsi-mpi3mr-mpi3mr_app.c-mpi3mr_map_data_buffer_dma()-warn:=
returning-instead-of-ENOMEM-is-sloppy
|   |-- fs-bcachefs-inode.c-bch2_delete_dead_inodes()-error:potentially-usi=
ng-uninitialized-ret-.
|   |-- lib-kunit-device.c-kunit_device_register_with_driver()-warn:passing=
-zero-to-ERR_CAST
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-drv-=
not-described-in-kunit_device_register_with_driver
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-name=
-not-described-in-kunit_device_register
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-name=
-not-described-in-kunit_device_register_with_driver
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-name=
-not-described-in-kunit_driver_create
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-test=
-not-described-in-kunit_device_register
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-test=
-not-described-in-kunit_device_register_with_driver
|   `-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-test=
-not-described-in-kunit_driver_create
|-- x86_64-rhel-8.3-bpf
|   |-- lib-aolib.h:error:TCP_AO_ADD_KEY-undeclared-(first-use-in-this-func=
tion)
|   |-- lib-aolib.h:error:invalid-use-of-undefined-type-struct-tcp_ao_add
|   |-- lib-aolib.h:error:storage-size-of-ao-isn-t-known
|   |-- lib-aolib.h:error:storage-size-of-ao2-isn-t-known
|   |-- lib-aolib.h:error:storage-size-of-key2-isn-t-known
|   |-- lib-aolib.h:error:storage-size-of-tmp-isn-t-known
|   |-- lib-aolib.h:error:variable-ao-has-initializer-but-incomplete-type
|   |-- lib-aolib.h:error:variable-ao2-has-initializer-but-incomplete-type
|   |-- lib-aolib.h:error:variable-key2-has-initializer-but-incomplete-type
|   |-- lib-aolib.h:error:variable-tmp-has-initializer-but-incomplete-type
|   |-- lib-kconfig.c:error:TCP_AO_ADD_KEY-undeclared-(first-use-in-this-fu=
nction)
|   |-- lib-kconfig.c:error:storage-size-of-tmp-isn-t-known
|   |-- lib-kconfig.c:error:variable-tmp-has-initializer-but-incomplete-typ=
e
|   |-- lib-repair.c:error:TCP_AO_REPAIR-undeclared-(first-use-in-this-func=
tion)
|   |-- lib-repair.c:error:conflicting-types-for-test_ao_checkpoint-have-vo=
id(int-struct-tcp_ao_repair-)
|   |-- lib-repair.c:error:conflicting-types-for-test_ao_restore-have-void(=
int-struct-tcp_ao_repair-)
|   |-- lib-repair.c:error:invalid-application-of-sizeof-to-incomplete-type=
-struct-tcp_ao_repair
|   |-- lib-sock.c:error:TCP_AO_GET_KEYS-undeclared-(first-use-in-this-func=
tion)
|   |-- lib-sock.c:error:TCP_AO_INFO-undeclared-(first-use-in-this-function=
)
|   |-- lib-sock.c:error:TCP_AO_MAXKEYLEN-undeclared-(first-use-in-this-fun=
ction)
|   |-- lib-sock.c:error:conflicting-types-for-test_cmp_getsockopt_setsocko=
pt-have-int(const-struct-tcp_ao_add-const-struct-tcp_ao_getsockopt-)
|   |-- lib-sock.c:error:conflicting-types-for-test_cmp_getsockopt_setsocko=
pt_ao-have-int(const-struct-tcp_ao_info_opt-const-struct-tcp_ao_info_opt-)
|   |-- lib-sock.c:error:conflicting-types-for-test_get_ao_info-have-int(in=
t-struct-tcp_ao_info_opt-)
|   |-- lib-sock.c:error:conflicting-types-for-test_get_one_ao-have-int(int=
-struct-tcp_ao_getsockopt-void-size_t-uint8_t-uint8_t-uint8_t)-aka-int(int-=
struct-tcp_ao_getsockopt-void-long-unsigned-int-unsigned-c
|   |-- lib-sock.c:error:conflicting-types-for-test_prepare_key_sockaddr-ha=
ve-int(struct-tcp_ao_add-const-char-void-size_t-_Bool-_Bool-uint8_t-uint8_t=
-uint8_t-uint8_t-uint8_t-uint8_t-uint8_t-const-char-)-aka-
|   |-- lib-sock.c:error:conflicting-types-for-test_set_ao_info-have-int(in=
t-struct-tcp_ao_info_opt-)
|   |-- lib-sock.c:error:invalid-application-of-sizeof-to-incomplete-type-s=
truct-tcp_ao_add
|   |-- lib-sock.c:error:invalid-application-of-sizeof-to-incomplete-type-s=
truct-tcp_ao_getsockopt
|   |-- lib-sock.c:error:invalid-application-of-sizeof-to-incomplete-type-s=
truct-tcp_ao_info_opt
|   |-- lib-sock.c:error:invalid-use-of-undefined-type-const-struct-tcp_ao_=
add
|   |-- lib-sock.c:error:invalid-use-of-undefined-type-const-struct-tcp_ao_=
getsockopt
|   |-- lib-sock.c:error:invalid-use-of-undefined-type-const-struct-tcp_ao_=
info_opt
|   |-- lib-sock.c:error:invalid-use-of-undefined-type-struct-tcp_ao_add
|   |-- lib-sock.c:error:invalid-use-of-undefined-type-struct-tcp_ao_getsoc=
kopt
|   |-- lib-sock.c:error:invalid-use-of-undefined-type-struct-tcp_ao_info_o=
pt
|   |-- lib-sock.c:error:storage-size-of-info-isn-t-known
|   |-- lib-sock.c:error:storage-size-of-tmp-isn-t-known
|   |-- lib-sock.c:error:variable-info-has-initializer-but-incomplete-type
|   `-- lib-sock.c:error:variable-tmp-has-initializer-but-incomplete-type
`-- xtensa-randconfig-001-20231222
    |-- WARNING:modpost:missing-MODULE_DESCRIPTION()-in-fs-exportfs-exportf=
s.o
    |-- drivers-gpu-drm-amd-amdgpu-..-display-dc-core-dc_state.c:warning:Ex=
cess-function-parameter-context-description-in-dc_state_rem_all_planes_for_=
stream
    |-- drivers-gpu-drm-amd-amdgpu-..-display-dc-core-dc_state.c:warning:Fu=
nction-parameter-or-struct-member-state-not-described-in-dc_state_rem_all_p=
lanes_for_stream
    `-- drivers-gpu-drm-amd-amdgpu-..-display-dc-dc_dmub_srv.c:warning:Func=
tion-parameter-or-struct-member-context-not-described-in-populate_subvp_cmd=
_drr_info
clang_recent_errors
|-- arm-defconfig
|   |-- WARNING:modpost:vmlinux:section-mismatch-in-reference:at91_poweroff=
_probe-(section:.text)-at91_wakeup_status-(section:.init.text)
|   |-- WARNING:modpost:vmlinux:section-mismatch-in-reference:at91_shdwc_pr=
obe-(section:.text)-at91_wakeup_status-(section:.init.text)
|   `-- drivers-gpu-drm-msm-disp-dpu1-dpu_encoder.c:warning:Excess-struct-m=
ember-debugfs_root-description-in-dpu_encoder_virt
|-- arm-randconfig-r052-20231222
|   `-- WARNING:modpost:vmlinux:section-mismatch-in-reference:at91_poweroff=
_probe-(section:.text)-at91_wakeup_status-(section:.init.text)
|-- arm64-allmodconfig
|   |-- drivers-gpu-drm-amd-amdgpu-..-display-dc-core-dc_state.c:warning:Ex=
cess-function-parameter-context-description-in-dc_state_rem_all_planes_for_=
stream
|   |-- drivers-gpu-drm-amd-amdgpu-..-display-dc-core-dc_state.c:warning:Fu=
nction-parameter-or-struct-member-state-not-described-in-dc_state_rem_all_p=
lanes_for_stream
|   |-- drivers-gpu-drm-amd-amdgpu-..-display-dc-dc_dmub_srv.c:warning:Func=
tion-parameter-or-struct-member-context-not-described-in-populate_subvp_cmd=
_drr_info
|   |-- drivers-gpu-drm-imagination-pvr_mmu.c:warning:Excess-struct-member-=
l0_free_tables-description-in-pvr_mmu_op_context
|   |-- drivers-gpu-drm-imagination-pvr_mmu.c:warning:Excess-struct-member-=
l0_prealloc_tables-description-in-pvr_mmu_op_context
|   |-- drivers-gpu-drm-imagination-pvr_mmu.c:warning:Excess-struct-member-=
l1_free_tables-description-in-pvr_mmu_op_context
|   |-- drivers-gpu-drm-imagination-pvr_mmu.c:warning:Excess-struct-member-=
l1_prealloc_tables-description-in-pvr_mmu_op_context
|   |-- drivers-gpu-drm-imagination-pvr_mmu.c:warning:Excess-struct-member-=
pvr_dev-description-in-pvr_mmu_backing_page
|   |-- drivers-gpu-drm-imagination-pvr_mmu.c:warning:Excess-struct-member-=
sgt-description-in-pvr_mmu_op_context
|   |-- drivers-gpu-drm-imagination-pvr_mmu.c:warning:Excess-struct-member-=
sgt_offset-description-in-pvr_mmu_op_context
|   |-- drivers-gpu-drm-msm-disp-dpu1-dpu_encoder.c:warning:Excess-struct-m=
ember-debugfs_root-description-in-dpu_encoder_virt
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-drv-=
not-described-in-kunit_device_register_with_driver
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-name=
-not-described-in-kunit_device_register
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-name=
-not-described-in-kunit_device_register_with_driver
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-name=
-not-described-in-kunit_driver_create
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-test=
-not-described-in-kunit_device_register
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-test=
-not-described-in-kunit_device_register_with_driver
|   `-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-test=
-not-described-in-kunit_driver_create
|-- arm64-allyesconfig
|   |-- drivers-dma-xilinx-xdma.c:warning:no-previous-prototype-for-functio=
n-xdma_prep_interleaved_dma
|   |-- drivers-dma-xilinx-xdma.c:warning:operator:has-lower-precedence-tha=
n-will-be-evaluated-first
|   |-- drivers-dma-xilinx-xdma.c:warning:variable-desc-is-uninitialized-wh=
en-used-here
|   |-- drivers-gpu-drm-amd-amdgpu-..-display-dc-core-dc_state.c:warning:Ex=
cess-function-parameter-context-description-in-dc_state_rem_all_planes_for_=
stream
|   |-- drivers-gpu-drm-amd-amdgpu-..-display-dc-core-dc_state.c:warning:Fu=
nction-parameter-or-struct-member-state-not-described-in-dc_state_rem_all_p=
lanes_for_stream
|   |-- drivers-gpu-drm-amd-amdgpu-..-display-dc-dc_dmub_srv.c:warning:Func=
tion-parameter-or-struct-member-context-not-described-in-populate_subvp_cmd=
_drr_info
|   |-- drivers-gpu-drm-imagination-pvr_mmu.c:warning:Excess-struct-member-=
l0_free_tables-description-in-pvr_mmu_op_context
|   |-- drivers-gpu-drm-imagination-pvr_mmu.c:warning:Excess-struct-member-=
l0_prealloc_tables-description-in-pvr_mmu_op_context
|   |-- drivers-gpu-drm-imagination-pvr_mmu.c:warning:Excess-struct-member-=
l1_free_tables-description-in-pvr_mmu_op_context
|   |-- drivers-gpu-drm-imagination-pvr_mmu.c:warning:Excess-struct-member-=
l1_prealloc_tables-description-in-pvr_mmu_op_context
|   |-- drivers-gpu-drm-imagination-pvr_mmu.c:warning:Excess-struct-member-=
pvr_dev-description-in-pvr_mmu_backing_page
|   |-- drivers-gpu-drm-imagination-pvr_mmu.c:warning:Excess-struct-member-=
sgt-description-in-pvr_mmu_op_context
|   |-- drivers-gpu-drm-imagination-pvr_mmu.c:warning:Excess-struct-member-=
sgt_offset-description-in-pvr_mmu_op_context
|   |-- drivers-gpu-drm-msm-disp-dpu1-dpu_encoder.c:warning:Excess-struct-m=
ember-debugfs_root-description-in-dpu_encoder_virt
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-drv-=
not-described-in-kunit_device_register_with_driver
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-name=
-not-described-in-kunit_device_register
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-name=
-not-described-in-kunit_device_register_with_driver
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-name=
-not-described-in-kunit_driver_create
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-test=
-not-described-in-kunit_device_register
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-test=
-not-described-in-kunit_device_register_with_driver
|   `-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-test=
-not-described-in-kunit_driver_create
|-- hexagon-allmodconfig
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-drv-=
not-described-in-kunit_device_register_with_driver
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-name=
-not-described-in-kunit_device_register
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-name=
-not-described-in-kunit_device_register_with_driver
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-name=
-not-described-in-kunit_driver_create
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-test=
-not-described-in-kunit_device_register
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-test=
-not-described-in-kunit_device_register_with_driver
|   `-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-test=
-not-described-in-kunit_driver_create
|-- hexagon-allyesconfig
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-drv-=
not-described-in-kunit_device_register_with_driver
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-name=
-not-described-in-kunit_device_register
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-name=
-not-described-in-kunit_device_register_with_driver
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-name=
-not-described-in-kunit_driver_create
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-test=
-not-described-in-kunit_device_register
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-test=
-not-described-in-kunit_device_register_with_driver
|   `-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-test=
-not-described-in-kunit_driver_create
|-- hexagon-randconfig-001-20231222
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-drv-=
not-described-in-kunit_device_register_with_driver
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-name=
-not-described-in-kunit_device_register
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-name=
-not-described-in-kunit_device_register_with_driver
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-name=
-not-described-in-kunit_driver_create
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-test=
-not-described-in-kunit_device_register
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-test=
-not-described-in-kunit_device_register_with_driver
|   `-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-test=
-not-described-in-kunit_driver_create
|-- i386-allmodconfig
|   |-- drivers-gpu-drm-msm-disp-dpu1-dpu_encoder.c:warning:Excess-struct-m=
ember-debugfs_root-description-in-dpu_encoder_virt
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-drv-=
not-described-in-kunit_device_register_with_driver
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-name=
-not-described-in-kunit_device_register
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-name=
-not-described-in-kunit_device_register_with_driver
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-name=
-not-described-in-kunit_driver_create
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-test=
-not-described-in-kunit_device_register
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-test=
-not-described-in-kunit_device_register_with_driver
|   `-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-test=
-not-described-in-kunit_driver_create
|-- i386-allyesconfig
|   |-- drivers-gpu-drm-msm-disp-dpu1-dpu_encoder.c:warning:Excess-struct-m=
ember-debugfs_root-description-in-dpu_encoder_virt
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-drv-=
not-described-in-kunit_device_register_with_driver
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-name=
-not-described-in-kunit_device_register
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-name=
-not-described-in-kunit_device_register_with_driver
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-name=
-not-described-in-kunit_driver_create
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-test=
-not-described-in-kunit_device_register
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-test=
-not-described-in-kunit_device_register_with_driver
|   `-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-test=
-not-described-in-kunit_driver_create
|-- i386-randconfig-013-20231222
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-drv-=
not-described-in-kunit_device_register_with_driver
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-name=
-not-described-in-kunit_device_register
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-name=
-not-described-in-kunit_device_register_with_driver
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-name=
-not-described-in-kunit_driver_create
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-test=
-not-described-in-kunit_device_register
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-test=
-not-described-in-kunit_device_register_with_driver
|   `-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-test=
-not-described-in-kunit_driver_create
|-- i386-randconfig-014-20231222
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-drv-=
not-described-in-kunit_device_register_with_driver
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-name=
-not-described-in-kunit_device_register
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-name=
-not-described-in-kunit_device_register_with_driver
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-name=
-not-described-in-kunit_driver_create
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-test=
-not-described-in-kunit_device_register
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-test=
-not-described-in-kunit_device_register_with_driver
|   `-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-test=
-not-described-in-kunit_driver_create
|-- i386-randconfig-016-20231222
|   `-- drivers-net-ethernet-intel-ice-ice_base.c:error:variable-has-incomp=
lete-type-struct-xsk_cb_desc
|-- mips-randconfig-r051-20231222
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-drv-=
not-described-in-kunit_device_register_with_driver
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-name=
-not-described-in-kunit_device_register
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-name=
-not-described-in-kunit_device_register_with_driver
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-name=
-not-described-in-kunit_driver_create
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-test=
-not-described-in-kunit_device_register
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-test=
-not-described-in-kunit_device_register_with_driver
|   `-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-test=
-not-described-in-kunit_driver_create
|-- mips-randconfig-r054-20231222
|   |-- WARNING:modpost:missing-MODULE_DESCRIPTION()-in-lib-zlib_inflate-zl=
ib_inflate.o
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-drv-=
not-described-in-kunit_device_register_with_driver
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-name=
-not-described-in-kunit_device_register
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-name=
-not-described-in-kunit_device_register_with_driver
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-name=
-not-described-in-kunit_driver_create
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-test=
-not-described-in-kunit_device_register
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-test=
-not-described-in-kunit_device_register_with_driver
|   `-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-test=
-not-described-in-kunit_driver_create
|-- powerpc-allmodconfig
|   |-- drivers-dma-xilinx-xdma.c:warning:no-previous-prototype-for-functio=
n-xdma_prep_interleaved_dma
|   |-- drivers-dma-xilinx-xdma.c:warning:operator:has-lower-precedence-tha=
n-will-be-evaluated-first
|   |-- drivers-dma-xilinx-xdma.c:warning:variable-desc-is-uninitialized-wh=
en-used-here
|   |-- drivers-gpu-drm-msm-disp-dpu1-dpu_encoder.c:warning:Excess-struct-m=
ember-debugfs_root-description-in-dpu_encoder_virt
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-drv-=
not-described-in-kunit_device_register_with_driver
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-name=
-not-described-in-kunit_device_register
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-name=
-not-described-in-kunit_device_register_with_driver
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-name=
-not-described-in-kunit_driver_create
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-test=
-not-described-in-kunit_device_register
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-test=
-not-described-in-kunit_device_register_with_driver
|   `-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-test=
-not-described-in-kunit_driver_create
|-- powerpc-allyesconfig
|   |-- drivers-dma-xilinx-xdma.c:warning:no-previous-prototype-for-functio=
n-xdma_prep_interleaved_dma
|   |-- drivers-dma-xilinx-xdma.c:warning:operator:has-lower-precedence-tha=
n-will-be-evaluated-first
|   |-- drivers-dma-xilinx-xdma.c:warning:variable-desc-is-uninitialized-wh=
en-used-here
|   |-- drivers-gpu-drm-msm-disp-dpu1-dpu_encoder.c:warning:Excess-struct-m=
ember-debugfs_root-description-in-dpu_encoder_virt
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-drv-=
not-described-in-kunit_device_register_with_driver
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-name=
-not-described-in-kunit_device_register
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-name=
-not-described-in-kunit_device_register_with_driver
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-name=
-not-described-in-kunit_driver_create
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-test=
-not-described-in-kunit_device_register
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-test=
-not-described-in-kunit_device_register_with_driver
|   `-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-test=
-not-described-in-kunit_driver_create
|-- s390-randconfig-002-20231222
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-drv-=
not-described-in-kunit_device_register_with_driver
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-name=
-not-described-in-kunit_device_register
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-name=
-not-described-in-kunit_device_register_with_driver
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-name=
-not-described-in-kunit_driver_create
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-test=
-not-described-in-kunit_device_register
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-test=
-not-described-in-kunit_device_register_with_driver
|   `-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-test=
-not-described-in-kunit_driver_create
|-- x86_64-allmodconfig
|   |-- drivers-dma-xilinx-xdma.c:warning:no-previous-prototype-for-functio=
n-xdma_prep_interleaved_dma
|   |-- drivers-dma-xilinx-xdma.c:warning:operator:has-lower-precedence-tha=
n-will-be-evaluated-first
|   |-- drivers-dma-xilinx-xdma.c:warning:variable-desc-is-uninitialized-wh=
en-used-here
|   |-- drivers-gpu-drm-amd-amdgpu-..-display-dc-core-dc_state.c:warning:Ex=
cess-function-parameter-context-description-in-dc_state_rem_all_planes_for_=
stream
|   |-- drivers-gpu-drm-amd-amdgpu-..-display-dc-core-dc_state.c:warning:Fu=
nction-parameter-or-struct-member-state-not-described-in-dc_state_rem_all_p=
lanes_for_stream
|   |-- drivers-gpu-drm-amd-amdgpu-..-display-dc-dc_dmub_srv.c:warning:Func=
tion-parameter-or-struct-member-context-not-described-in-populate_subvp_cmd=
_drr_info
|   |-- drivers-gpu-drm-amd-amdgpu-..-display-dc-hwss-dcn35-dcn35_hwseq.c:w=
arning:This-comment-starts-with-but-isn-t-a-kernel-doc-comment.-Refer-Docum=
entation-doc-guide-kernel-doc.rst
|   |-- drivers-gpu-drm-msm-disp-dpu1-dpu_encoder.c:warning:Excess-struct-m=
ember-debugfs_root-description-in-dpu_encoder_virt
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-drv-=
not-described-in-kunit_device_register_with_driver
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-name=
-not-described-in-kunit_device_register
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-name=
-not-described-in-kunit_device_register_with_driver
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-name=
-not-described-in-kunit_driver_create
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-test=
-not-described-in-kunit_device_register
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-test=
-not-described-in-kunit_device_register_with_driver
|   `-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-test=
-not-described-in-kunit_driver_create
|-- x86_64-allyesconfig
|   |-- drivers-dma-xilinx-xdma.c:warning:no-previous-prototype-for-functio=
n-xdma_prep_interleaved_dma
|   |-- drivers-dma-xilinx-xdma.c:warning:operator:has-lower-precedence-tha=
n-will-be-evaluated-first
|   |-- drivers-dma-xilinx-xdma.c:warning:variable-desc-is-uninitialized-wh=
en-used-here
|   |-- drivers-gpu-drm-amd-amdgpu-..-display-dc-core-dc_state.c:warning:Ex=
cess-function-parameter-context-description-in-dc_state_rem_all_planes_for_=
stream
|   |-- drivers-gpu-drm-amd-amdgpu-..-display-dc-core-dc_state.c:warning:Fu=
nction-parameter-or-struct-member-state-not-described-in-dc_state_rem_all_p=
lanes_for_stream
|   |-- drivers-gpu-drm-amd-amdgpu-..-display-dc-dc_dmub_srv.c:warning:Func=
tion-parameter-or-struct-member-context-not-described-in-populate_subvp_cmd=
_drr_info
|   |-- drivers-gpu-drm-amd-amdgpu-..-display-dc-hwss-dcn35-dcn35_hwseq.c:w=
arning:This-comment-starts-with-but-isn-t-a-kernel-doc-comment.-Refer-Docum=
entation-doc-guide-kernel-doc.rst
|   |-- drivers-gpu-drm-msm-disp-dpu1-dpu_encoder.c:warning:Excess-struct-m=
ember-debugfs_root-description-in-dpu_encoder_virt
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-drv-=
not-described-in-kunit_device_register_with_driver
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-name=
-not-described-in-kunit_device_register
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-name=
-not-described-in-kunit_device_register_with_driver
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-name=
-not-described-in-kunit_driver_create
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-test=
-not-described-in-kunit_device_register
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-test=
-not-described-in-kunit_device_register_with_driver
|   `-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-test=
-not-described-in-kunit_driver_create
|-- x86_64-randconfig-001-20231222
|   |-- drivers-gpu-drm-amd-amdgpu-..-display-dc-core-dc_state.c:warning:Ex=
cess-function-parameter-context-description-in-dc_state_rem_all_planes_for_=
stream
|   |-- drivers-gpu-drm-amd-amdgpu-..-display-dc-core-dc_state.c:warning:Fu=
nction-parameter-or-struct-member-state-not-described-in-dc_state_rem_all_p=
lanes_for_stream
|   |-- drivers-gpu-drm-amd-amdgpu-..-display-dc-dc_dmub_srv.c:warning:Func=
tion-parameter-or-struct-member-context-not-described-in-populate_subvp_cmd=
_drr_info
|   |-- drivers-gpu-drm-amd-amdgpu-..-display-dc-hwss-dcn35-dcn35_hwseq.c:w=
arning:This-comment-starts-with-but-isn-t-a-kernel-doc-comment.-Refer-Docum=
entation-doc-guide-kernel-doc.rst
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-drv-=
not-described-in-kunit_device_register_with_driver
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-name=
-not-described-in-kunit_device_register
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-name=
-not-described-in-kunit_device_register_with_driver
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-name=
-not-described-in-kunit_driver_create
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-test=
-not-described-in-kunit_device_register
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-test=
-not-described-in-kunit_device_register_with_driver
|   `-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-test=
-not-described-in-kunit_driver_create
|-- x86_64-randconfig-006-20231222
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-drv-=
not-described-in-kunit_device_register_with_driver
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-name=
-not-described-in-kunit_device_register
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-name=
-not-described-in-kunit_device_register_with_driver
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-name=
-not-described-in-kunit_driver_create
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-test=
-not-described-in-kunit_device_register
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-test=
-not-described-in-kunit_device_register_with_driver
|   `-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-test=
-not-described-in-kunit_driver_create
|-- x86_64-randconfig-121-20231222
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-drv-=
not-described-in-kunit_device_register_with_driver
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-name=
-not-described-in-kunit_device_register
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-name=
-not-described-in-kunit_device_register_with_driver
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-name=
-not-described-in-kunit_driver_create
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-test=
-not-described-in-kunit_device_register
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-test=
-not-described-in-kunit_device_register_with_driver
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-test=
-not-described-in-kunit_driver_create
|   |-- mm-kasan-common.c:sparse:sparse:incorrect-type-in-argument-(differe=
nt-base-types)-expected-restricted-gfp_t-usertype-flags-got-unsigned-long-u=
sertype-size
|   `-- mm-kasan-common.c:sparse:sparse:symbol-unpoison_slab_object-was-not=
-declared.-Should-it-be-static
|-- x86_64-randconfig-122-20231222
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-drv-=
not-described-in-kunit_device_register_with_driver
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-name=
-not-described-in-kunit_device_register
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-name=
-not-described-in-kunit_device_register_with_driver
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-name=
-not-described-in-kunit_driver_create
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-test=
-not-described-in-kunit_device_register
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-test=
-not-described-in-kunit_device_register_with_driver
|   `-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-test=
-not-described-in-kunit_driver_create
|-- x86_64-randconfig-123-20231222
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-drv-=
not-described-in-kunit_device_register_with_driver
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-name=
-not-described-in-kunit_device_register
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-name=
-not-described-in-kunit_device_register_with_driver
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-name=
-not-described-in-kunit_driver_create
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-test=
-not-described-in-kunit_device_register
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-test=
-not-described-in-kunit_device_register_with_driver
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-test=
-not-described-in-kunit_driver_create
|   |-- mm-kasan-common.c:sparse:sparse:incorrect-type-in-argument-(differe=
nt-base-types)-expected-restricted-gfp_t-usertype-flags-got-unsigned-long-u=
sertype-size
|   `-- mm-kasan-common.c:sparse:sparse:symbol-unpoison_slab_object-was-not=
-declared.-Should-it-be-static
|-- x86_64-randconfig-r132-20231222
|   |-- drivers-hwmon-max31827.c:sparse:sparse:dubious:x-y
|   |-- fs-bcachefs-btree_iter.c:sparse:sparse:incompatible-types-in-compar=
ison-expression-(different-address-spaces):
|   |-- fs-bcachefs-btree_iter.c:sparse:struct-btree_path
|   |-- fs-bcachefs-btree_iter.c:sparse:struct-btree_path-noderef-__rcu
|   |-- fs-bcachefs-btree_locking.c:sparse:sparse:incompatible-types-in-com=
parison-expression-(different-address-spaces):
|   |-- fs-bcachefs-btree_locking.c:sparse:struct-btree_path
|   |-- fs-bcachefs-btree_locking.c:sparse:struct-btree_path-noderef-__rcu
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-drv-=
not-described-in-kunit_device_register_with_driver
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-name=
-not-described-in-kunit_device_register
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-name=
-not-described-in-kunit_device_register_with_driver
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-name=
-not-described-in-kunit_driver_create
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-test=
-not-described-in-kunit_device_register
|   |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-test=
-not-described-in-kunit_device_register_with_driver
|   `-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-test=
-not-described-in-kunit_driver_create
`-- x86_64-rhel-8.3-rust
    |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-drv-=
not-described-in-kunit_device_register_with_driver
    |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-name=
-not-described-in-kunit_device_register
    |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-name=
-not-described-in-kunit_device_register_with_driver
    |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-name=
-not-described-in-kunit_driver_create
    |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-test=
-not-described-in-kunit_device_register
    |-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-test=
-not-described-in-kunit_device_register_with_driver
    `-- lib-kunit-device.c:warning:Function-parameter-or-struct-member-test=
-not-described-in-kunit_driver_create

elapsed time: 1537m

configs tested: 177
configs skipped: 3

tested configs:
alpha                             allnoconfig   gcc =20
alpha                            allyesconfig   gcc =20
alpha                               defconfig   gcc =20
arc                              allmodconfig   gcc =20
arc                               allnoconfig   gcc =20
arc                              allyesconfig   gcc =20
arc                      axs103_smp_defconfig   gcc =20
arc                                 defconfig   gcc =20
arc                   randconfig-001-20231222   gcc =20
arc                   randconfig-002-20231222   gcc =20
arm                              allmodconfig   gcc =20
arm                               allnoconfig   gcc =20
arm                              allyesconfig   gcc =20
arm                                 defconfig   clang
arm                           h3600_defconfig   gcc =20
arm                        keystone_defconfig   gcc =20
arm                            mmp2_defconfig   clang
arm                   randconfig-001-20231222   gcc =20
arm                   randconfig-002-20231222   gcc =20
arm                   randconfig-003-20231222   gcc =20
arm                   randconfig-004-20231222   gcc =20
arm                         wpcm450_defconfig   gcc =20
arm64                            allmodconfig   clang
arm64                             allnoconfig   gcc =20
arm64                               defconfig   gcc =20
arm64                 randconfig-001-20231222   gcc =20
arm64                 randconfig-002-20231222   gcc =20
arm64                 randconfig-003-20231222   gcc =20
arm64                 randconfig-004-20231222   gcc =20
csky                             allmodconfig   gcc =20
csky                              allnoconfig   gcc =20
csky                             allyesconfig   gcc =20
csky                                defconfig   gcc =20
csky                  randconfig-001-20231222   gcc =20
csky                  randconfig-002-20231222   gcc =20
hexagon                          allmodconfig   clang
hexagon                           allnoconfig   clang
hexagon                          allyesconfig   clang
hexagon                             defconfig   clang
hexagon               randconfig-001-20231222   clang
hexagon               randconfig-002-20231222   clang
i386                             allmodconfig   clang
i386                              allnoconfig   clang
i386                             allyesconfig   clang
i386         buildonly-randconfig-001-20231222   gcc =20
i386         buildonly-randconfig-002-20231222   gcc =20
i386         buildonly-randconfig-003-20231222   gcc =20
i386         buildonly-randconfig-004-20231222   gcc =20
i386         buildonly-randconfig-005-20231222   gcc =20
i386         buildonly-randconfig-006-20231222   gcc =20
i386                                defconfig   gcc =20
i386                  randconfig-001-20231222   gcc =20
i386                  randconfig-002-20231222   gcc =20
i386                  randconfig-003-20231222   gcc =20
i386                  randconfig-004-20231222   gcc =20
i386                  randconfig-005-20231222   gcc =20
i386                  randconfig-006-20231222   gcc =20
i386                  randconfig-011-20231222   clang
i386                  randconfig-012-20231222   clang
i386                  randconfig-013-20231222   clang
i386                  randconfig-014-20231222   clang
i386                  randconfig-015-20231222   clang
i386                  randconfig-016-20231222   clang
loongarch                        allmodconfig   gcc =20
loongarch                         allnoconfig   gcc =20
loongarch                           defconfig   gcc =20
loongarch                 loongson3_defconfig   gcc =20
loongarch             randconfig-001-20231222   gcc =20
loongarch             randconfig-002-20231222   gcc =20
m68k                             allmodconfig   gcc =20
m68k                              allnoconfig   gcc =20
m68k                             allyesconfig   gcc =20
m68k                                defconfig   gcc =20
microblaze                       allmodconfig   gcc =20
microblaze                        allnoconfig   gcc =20
microblaze                       allyesconfig   gcc =20
microblaze                          defconfig   gcc =20
mips                              allnoconfig   clang
mips                             allyesconfig   gcc =20
mips                        qi_lb60_defconfig   clang
nios2                            allmodconfig   gcc =20
nios2                             allnoconfig   gcc =20
nios2                            allyesconfig   gcc =20
nios2                               defconfig   gcc =20
nios2                 randconfig-001-20231222   gcc =20
nios2                 randconfig-002-20231222   gcc =20
openrisc                          allnoconfig   gcc =20
openrisc                         allyesconfig   gcc =20
openrisc                            defconfig   gcc =20
openrisc                  or1klitex_defconfig   gcc =20
parisc                           allmodconfig   gcc =20
parisc                            allnoconfig   gcc =20
parisc                           allyesconfig   gcc =20
parisc                              defconfig   gcc =20
parisc                randconfig-001-20231222   gcc =20
parisc                randconfig-002-20231222   gcc =20
parisc64                            defconfig   gcc =20
powerpc                     akebono_defconfig   clang
powerpc                          allmodconfig   clang
powerpc                           allnoconfig   gcc =20
powerpc                          allyesconfig   clang
powerpc                       eiger_defconfig   gcc =20
powerpc                     powernv_defconfig   clang
powerpc                     ppa8548_defconfig   gcc =20
powerpc                       ppc64_defconfig   gcc =20
powerpc               randconfig-001-20231222   gcc =20
powerpc               randconfig-002-20231222   gcc =20
powerpc               randconfig-003-20231222   gcc =20
powerpc64             randconfig-001-20231222   gcc =20
powerpc64             randconfig-002-20231222   gcc =20
powerpc64             randconfig-003-20231222   gcc =20
riscv                            allmodconfig   gcc =20
riscv                             allnoconfig   clang
riscv                            allyesconfig   gcc =20
riscv                               defconfig   gcc =20
riscv                 randconfig-001-20231222   gcc =20
riscv                 randconfig-002-20231222   gcc =20
riscv                          rv32_defconfig   clang
s390                             allmodconfig   gcc =20
s390                              allnoconfig   gcc =20
s390                             allyesconfig   gcc =20
s390                                defconfig   gcc =20
s390                  randconfig-001-20231222   clang
s390                  randconfig-002-20231222   clang
sh                               allmodconfig   gcc =20
sh                                allnoconfig   gcc =20
sh                               allyesconfig   gcc =20
sh                                  defconfig   gcc =20
sh                    randconfig-001-20231222   gcc =20
sh                    randconfig-002-20231222   gcc =20
sh                           se7750_defconfig   gcc =20
sparc                            allmodconfig   gcc =20
sparc64                          allmodconfig   gcc =20
sparc64                          allyesconfig   gcc =20
sparc64                             defconfig   gcc =20
sparc64               randconfig-001-20231222   gcc =20
sparc64               randconfig-002-20231222   gcc =20
um                               allmodconfig   clang
um                                allnoconfig   clang
um                               allyesconfig   clang
um                                  defconfig   gcc =20
um                             i386_defconfig   gcc =20
um                    randconfig-001-20231222   gcc =20
um                    randconfig-002-20231222   gcc =20
um                           x86_64_defconfig   gcc =20
x86_64                            allnoconfig   gcc =20
x86_64                           allyesconfig   clang
x86_64       buildonly-randconfig-001-20231222   gcc =20
x86_64       buildonly-randconfig-002-20231222   gcc =20
x86_64       buildonly-randconfig-003-20231222   gcc =20
x86_64       buildonly-randconfig-004-20231222   gcc =20
x86_64       buildonly-randconfig-005-20231222   gcc =20
x86_64       buildonly-randconfig-006-20231222   gcc =20
x86_64                              defconfig   gcc =20
x86_64                randconfig-001-20231222   clang
x86_64                randconfig-002-20231222   clang
x86_64                randconfig-003-20231222   clang
x86_64                randconfig-004-20231222   clang
x86_64                randconfig-005-20231222   clang
x86_64                randconfig-006-20231222   clang
x86_64                randconfig-011-20231222   gcc =20
x86_64                randconfig-012-20231222   gcc =20
x86_64                randconfig-013-20231222   gcc =20
x86_64                randconfig-014-20231222   gcc =20
x86_64                randconfig-015-20231222   gcc =20
x86_64                randconfig-016-20231222   gcc =20
x86_64                randconfig-071-20231222   gcc =20
x86_64                randconfig-072-20231222   gcc =20
x86_64                randconfig-073-20231222   gcc =20
x86_64                randconfig-074-20231222   gcc =20
x86_64                randconfig-075-20231222   gcc =20
x86_64                randconfig-076-20231222   gcc =20
x86_64                          rhel-8.3-rust   clang
xtensa                            allnoconfig   gcc =20
xtensa                       common_defconfig   gcc =20
xtensa                randconfig-001-20231222   gcc =20
xtensa                randconfig-002-20231222   gcc =20

--=20
0-DAY CI Kernel Test Service
https://github.com/intel/lkp-tests/wiki

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/202312231534.UWFO81PH-lkp%40intel.com.
